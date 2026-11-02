"""Gestor del flujo de corrección: detectar -> Claude propone -> se verifica -> el usuario decide
-> (solo entonces) se aplica con copia de seguridad -> se comprueba -> (rollback si hace falta).

Panel y Telegram llaman a los mismos métodos de este gestor, así que las reglas son las mismas
venga la orden de donde venga.
"""
from __future__ import annotations

import hashlib
import logging
import queue
import threading
import time

from . import claude, compatibilidad, consumo, telegram
from .aplicar import Aplicador, ErrorAplicacion
from .modelo import ORDEN_SEVERIDAD, Componente
from .planes import Planes, aprobados, pendientes

log = logging.getLogger("vigilante.correcciones")


class Gestor:
    def __init__(self, vigilante):
        self.v = vigilante
        self.cfg = vigilante.cfg
        self.planes = Planes(vigilante.datos)
        self.consumo = consumo.Consumo(vigilante.datos)
        self._tamanos: dict = {}       # (raiz, paquete) -> (instante, caracteres de contexto)
        self.bot = telegram.Bot(self.cfg["avisos"], self._boton)
        self.cola: queue.Queue = queue.Queue()
        self.cerrojo_aplicar = threading.Lock()
        threading.Thread(target=self._trabajador, daemon=True, name="planes").start()

    def arrancar_bot(self):
        self.bot.arrancar()

    # ------------------------------------------------------------------ creación de planes
    def revisar_ciclo(self, nuevos, componentes: dict, actuales: dict):
        """Tras cada ciclo: crear planes para componentes con vulnerabilidades nuevas y
        marcar como obsoletos los planes cuyo componente ya no tiene vulnerabilidades."""
        con_vulns = {v["componente"] for v in actuales.values()}
        for p in self.planes.todos():
            if p["estado"] in ("pendiente_aprobacion", "analizando") and p["componente"]["clave"] not in con_vulns:
                p["estado"] = "obsoleto"
                self.planes.evento(p, "obsoleto: las vulnerabilidades ya no aparecen (¿actualizado por otra vía?)")
        cc = self.cfg["claude"]
        # Por defecto Claude NO se pone a trabajar solo: el usuario lo pide (panel o Telegram).
        if not claude.disponible(cc) or not self.modo_auto():
            return
        minimo = ORDEN_SEVERIDAD[cc.get("severidad_minima", "ALTA")]
        por_comp: dict[str, list] = {}
        for h in nuevos:
            if ORDEN_SEVERIDAD[h.severidad] >= minimo or h.critico:
                por_comp.setdefault(h.componente, []).append(h)
        orden = sorted(por_comp, key=lambda k: (not any(h.critico for h in por_comp[k]),
                                                -max(h.cvss or 0 for h in por_comp[k])))
        creados = 0
        for clave in orden:
            if creados >= int(cc.get("max_planes_por_ciclo", 3)):
                break
            comp = componentes.get(clave)
            if not comp or self.planes.abierto_para(clave):
                continue
            todos = [v for v in actuales.values() if v["componente"] == clave]
            raiz = self._raiz(comp)
            if not raiz:      # sin código montado no hay nada que modificar: no gasta cupo de planes
                log.info("%s (%s): sin código del proyecto montado, no se prepara plan", comp.nombre, comp.app or "-")
                continue
            creados += 1
            plan = self.planes.crear(comp.to_dict(), todos, raiz)
            self.cola.put(plan["id"])
            log.info("Plan %s creado para %s %s (%d vulnerabilidades)", plan["id"], comp.nombre, comp.version, len(todos))

    def modo_auto(self) -> bool:
        return self.cfg["claude"].get("modo", "a_peticion") == "auto"

    # ------------------------------------------------------------------ resolución A PETICIÓN del usuario
    @staticmethod
    def _id_corto(clave: str) -> str:
        return hashlib.sha1(clave.encode()).hexdigest()[:10]

    def _comp_por_id(self, id_corto: str) -> dict | None:
        return next((c for c in self.v.estado.get("componentes", []) if self._id_corto(c["clave"]) == id_corto), None)

    @staticmethod
    def _como_objeto(d: dict) -> Componente:
        return Componente(**{k: d[k] for k in ("nombre", "version", "tipo", "ecosistema", "origen", "detalle",
                                               "contenedor", "app") if k in d})

    def _vulns_de(self, clave: str) -> list[dict]:
        return [v for v in self.v.estado.get("hallazgos", {}).values() if v["componente"] == clave]

    def estado_resolver(self, comp: dict) -> tuple[str, str]:
        """Qué se puede hacer con un componente: ('plan', id) | ('disponible', '') | ('sin_clave'|'sin_codigo'|
        'sin_vulns', motivo)."""
        if not self._vulns_de(comp["clave"]):
            return "sin_vulns", "Sin vulnerabilidades"
        abierto = self.planes.abierto_para(comp["clave"])
        if abierto:
            return "plan", abierto["id"]
        if not claude.disponible(self.cfg["claude"]):
            return "sin_clave", "Falta Claude Code con sesión iniciada o token"
        if not self._raiz(comp):
            return "sin_codigo", "Sin código del proyecto montado"
        return "disponible", ""

    # ------------------------------------------------------------------ modelo, razonamiento y consumo
    def eleccion(self, modelo: str | None = None, esfuerzo: str | None = None) -> tuple[str, str]:
        """Modelo y razonamiento pedidos, o los de la configuración si no se piden o no son válidos."""
        cc = self.cfg["claude"]
        m = modelo if modelo in consumo.NOMBRE_MODELO else cc.get("modelo", "claude-opus-5-5")
        e = esfuerzo if esfuerzo in consumo.NOMBRE_ESFUERZO else cc.get("esfuerzo", "high")
        return m, e

    def _cfg_claude(self, plan) -> dict:
        elegido = plan.get("claude") or {}
        m, e = self.eleccion(elegido.get("modelo"), elegido.get("esfuerzo"))
        return {**self.cfg["claude"], "modelo": m, "esfuerzo": e}

    def _tamano_peticion(self, comp: dict) -> int:
        """Caracteres aproximados de lo que se le enviará a Claude (para estimar el coste)."""
        raiz = self._raiz(comp)
        clave = (comp.get("equipo", ""), raiz, comp["nombre"])
        previo = self._tamanos.get(clave)
        if not previo or time.monotonic() - previo[0] > 600:
            try:
                eq = self.equipo_de(comp)
                n = len(eq.contexto(raiz, comp["nombre"])) if raiz and eq else 0
            except OSError:
                n = 0
            previo = self._tamanos[clave] = (time.monotonic(), n)
        return previo[1] + 3000 + 300 * min(40, len(self._vulns_de(comp["clave"])))

    def estimaciones(self, comps: list[dict]) -> dict:
        """{"modelo|esfuerzo": estimación} sumando los componentes indicados (para el diálogo del panel)."""
        tamanos = [self._tamano_peticion(c) for c in comps]
        web = self.cfg["claude"].get("investigar_web", True)
        out = {}
        for m in consumo.NOMBRE_MODELO:
            for e in consumo.NOMBRE_ESFUERZO:
                ests = [self.consumo.estimar(m, e, t, web) for t in tamanos]
                if not ests:
                    continue
                total = dict(ests[0], coste_usd=round(sum(x["coste_usd"] for x in ests), 4))
                total["plan"] = {k: dict(v, delta=None if v["delta"] is None else
                                         round(sum(x["plan"][k]["delta"] for x in ests), 4))
                                 for k, v in ests[0]["plan"].items()}
                out[f"{m}|{e}"] = total
        return out

    def _registrar_consumo(self, plan, tipo, uso):
        if uso.get("duracion_s") is None:       # no llegó a ejecutarse
            return
        r = self.consumo.registrar(plan, tipo, uso)
        d = r.get("delta") or {}
        self.planes.evento(plan, f"consumo de Claude ({tipo}): {consumo.NOMBRE_MODELO.get(r['modelo'], r['modelo'])}, "
                                 f"razonamiento {consumo.NOMBRE_ESFUERZO.get(r['esfuerzo'], r['esfuerzo']).lower()}, "
                                 f"{r['duracion_s']:.0f} s, ventana 5 h +{consumo.pct(d.get('five_hour'))}, "
                                 f"semanal +{consumo.pct(d.get('seven_day'))}, equivalente API {consumo.usd(r['coste_usd'])}")

    def solicitar_componente(self, clave: str, por: str, modelo: str | None = None, esfuerzo: str | None = None) -> str:
        """El usuario pide EXPLÍCITAMENTE que Claude prepare una corrección para un componente."""
        comp = next((c for c in self.v.estado.get("componentes", []) if c["clave"] == clave), None)
        if not comp:
            return "Ese componente ya no existe (puede que se haya actualizado)."
        estado, dato = self.estado_resolver(comp)
        if estado == "plan":
            return f"Ya hay un plan en curso para {comp['nombre']}: míralo en Correcciones."
        if estado != "disponible":
            return f"No se puede resolver {comp['nombre']}: {dato.lower()}."
        raiz = self._raiz(comp)
        plan = self.planes.crear(comp, self._vulns_de(clave), raiz)
        plan["solicitado_por"] = por
        m, e = self.eleccion(modelo, esfuerzo)
        est = self.consumo.estimar(m, e, self._tamano_peticion(comp), self.cfg["claude"].get("investigar_web", True))
        plan["claude"] = {"modelo": m, "esfuerzo": e, "estimacion": est, "llamadas": []}
        self.planes.evento(plan, f"corrección solicitada por {por} con {consumo.NOMBRE_MODELO[m]}, razonamiento "
                                 f"{consumo.NOMBRE_ESFUERZO[e].lower()}: Claude empieza a trabajar", por)
        self.cola.put(plan["id"])
        log.warning("Plan %s solicitado por %s para %s %s", plan["id"], por, comp["nombre"], comp["version"])
        return (f"Claude está preparando la corrección de {comp['nombre']} {comp['version']}. "
                "Aparecerá en Correcciones para que la revises; no se aplicará nada sin tu aprobación.")

    def candidatos_app(self, app: str) -> list[dict]:
        """Componentes de la app con vulnerabilidades relevantes que se pueden resolver ahora."""
        cc = self.cfg["claude"]
        minimo = ORDEN_SEVERIDAD[cc.get("severidad_minima", "ALTA")]
        out = []
        for c in self.v.estado.get("componentes", []):
            if c.get("app") != app or self.estado_resolver(c)[0] != "disponible":
                continue
            vs = self._vulns_de(c["clave"])
            if any(ORDEN_SEVERIDAD[v["severidad"]] >= minimo or v["critico"] for v in vs):
                out.append((c, vs))
        out.sort(key=lambda t: (not any(v["critico"] for v in t[1]), -max((v.get("cvss") or 0) for v in t[1])))
        return [c for c, _ in out][: int(cc.get("max_planes_por_solicitud", 6))]

    def solicitar_app(self, app: str, por: str, modelo: str | None = None, esfuerzo: str | None = None) -> str:
        """El usuario pide EXPLÍCITAMENTE resolver los componentes con vulnerabilidades importantes de una app."""
        cands = self.candidatos_app(app)
        if not cands:
            return f"{app}: no hay nada que Claude pueda resolver ahora (sin vulnerabilidades relevantes, sin clave o sin código montado)."
        for c in cands:
            self.solicitar_componente(c["clave"], por, modelo, esfuerzo)
        return (f"Claude está preparando {len(cands)} corrección(es) para {app}. "
                "Irán apareciendo en Correcciones; no se aplicará nada sin tu aprobación.")

    def ofrecer_resolucion(self, hallazgos):
        """Tras un análisis, AVISA por Telegram de qué componentes se podrían resolver con Claude y deja un botón.
        No llama a Claude: solo ofrece. Máximo 5 mensajes por análisis."""
        cc = self.cfg["claude"]
        if self.modo_auto() or not (self.bot.activo and claude.disponible(cc)):
            return
        minimo = ORDEN_SEVERIDAD[cc.get("severidad_minima", "ALTA")]
        por_comp: dict[str, list] = {}
        for h in hallazgos:
            if ORDEN_SEVERIDAD[h.severidad] >= minimo or h.critico:
                por_comp.setdefault(h.componente, []).append(h)
        enviados = 0
        for clave, hs in sorted(por_comp.items(), key=lambda kv: (not any(h.critico for h in kv[1]),
                                                                  -max(h.cvss or 0 for h in kv[1]))):
            comp = next((c for c in self.v.estado.get("componentes", []) if c["clave"] == clave), None)
            if not comp or self.estado_resolver(comp)[0] != "disponible" or enviados >= 5:
                continue
            enviados += 1
            criticas = sum(1 for v in self._vulns_de(clave) if v["critico"])
            self.bot.enviar(
                f"<b>{telegram.E(comp['nombre'])} {telegram.E(comp['version'])}</b>"
                f"{(' · app ' + telegram.E(comp['app'])) if comp.get('app') else ''}\n"
                f"{len(self._vulns_de(clave))} vulnerabilidad(es), {criticas} crítica(s).\n\n"
                "¿Quieres que Claude prepare una corrección? Solo lo hará si pulsas el botón, y nada se "
                "aplicará sin tu aprobación.",
                [[telegram.b("Resolver con Claude", "rsv", self._id_corto(clave)),
                  telegram.b("Ahora no", "nop", self._id_corto(clave))]], silencioso=True)

    def _texto_estimacion(self, comp: dict) -> str:
        m, e = self.eleccion()
        return consumo.texto_estimacion(self.consumo.estimar(m, e, self._tamano_peticion(comp),
                                                             self.cfg["claude"].get("investigar_web", True)))

    def equipo_de(self, x):
        """Equipo (servidor) de un componente, como objeto o dict, o de un plan."""
        if isinstance(x, dict) and "componente" in x:
            x = x["componente"]
        id_ = x.get("equipo", "") if isinstance(x, dict) else getattr(x, "equipo", "")
        return self.v.equipo(id_)

    def _raiz(self, comp) -> str:
        """Carpeta del proyecto de la app del componente ('' si no hay código montado que modificar)."""
        eq = self.equipo_de(comp)          # con el dict original: _como_objeto no conserva el equipo
        if eq is None:
            return ""
        return eq.raiz(self._como_objeto(comp) if isinstance(comp, dict) else comp)

    def _trabajador(self):
        while True:
            plan_id = self.cola.get()
            try:
                self.procesar(plan_id)
            except Exception:  # noqa: BLE001
                log.exception("Error procesando el plan %s", plan_id)
            finally:
                self.cola.task_done()

    # ------------------------------------------------------------------ análisis + verificación
    def procesar(self, plan_id):
        plan = self.planes.obtener(plan_id)
        if not plan["raiz"]:
            plan["estado"] = "error"
            self.planes.evento(plan, "sin código del proyecto montado: no se pueden proponer cambios")
            return
        runtimes = {c["nombre"]: c["version"] for c in self.v.estado.get("componentes", []) if c["tipo"] == "runtime"}
        from .motor import version_minima_segura
        minima = version_minima_segura(h.get("corregido_en") or [] for h in plan["hallazgos"])
        plan["compatibilidad"] = compatibilidad.revisar(self.v.cache, plan["componente"], minima, runtimes)
        self.planes.evento(plan, f"revisión automática de compatibilidad hacia {minima or '¿?'}")

        eq = self.equipo_de(plan)
        capacidades = eq.capacidades()
        contexto = eq.contexto(plan["raiz"], plan["componente"]["nombre"])
        cfg_claude = self._cfg_claude(plan)
        uso: dict = {}
        try:
            analisis = claude.analizar(cfg_claude, plan, runtimes, capacidades, contexto, uso)
        except claude.ErrorClaude as e:
            plan["estado"] = "error"
            self._registrar_consumo(plan, "analisis", uso)
            self.planes.evento(plan, f"Claude no pudo analizar: {e}")
            self.v.avisador.enviar(f"No se pudo preparar corrección para {plan['componente']['nombre']}", str(e))
            return
        self._registrar_consumo(plan, "analisis", uso)
        self._incorporar(plan, analisis, runtimes)
        self.planes.evento(plan, f"Claude propone {len(plan['cambios'])} cambio(s) → {analisis.get('version_objetivo')}")
        if not plan["cambios"]:
            plan["estado"] = "sin_cambios"
            self.planes.evento(plan, "Claude no propone cambios: " + (analisis.get("estrategia") or "sin motivo indicado"))
            self.v.avisador.enviar(f"Claude no propone cambios para {plan['componente']['nombre']}",
                                   analisis.get("estrategia") or "Sin motivo indicado.")
            return

        plan["estado"] = "verificando"
        self.planes.guardar(plan)
        plan["verificacion"] = eq.verificar(plan)
        self.planes.evento(plan, f"verificación: {plan['verificacion']['estado']}")

        if plan["verificacion"]["estado"] in ("fallo", "parcial") and self.cfg["claude"].get("reintento_si_falla", True):
            fallo = "\n".join(f"[{'OK' if p['ok'] else ('FALLO' if p['ok'] is False else 'INFO')}] {p['paso']}: "
                              f"{p['detalle']}\n{p.get('salida', '')[-1500:]}" for p in plan["verificacion"]["pasos"])
            uso = {}
            try:
                analisis = claude.corregir(cfg_claude, plan, runtimes, capacidades, contexto, fallo, uso)
                self._registrar_consumo(plan, "reintento", uso)
                previa = plan["verificacion"]
                self._incorporar(plan, analisis, runtimes)
                plan["verificacion"] = eq.verificar(plan)
                plan["verificacion"]["intento_previo"] = {"estado": previa["estado"], "pasos": previa["pasos"]}
                self.planes.evento(plan, f"Claude corrigió el plan tras el fallo; nueva verificación: "
                                         f"{plan['verificacion']['estado']}")
            except claude.ErrorClaude as e:
                self._registrar_consumo(plan, "reintento", uso)
                self.planes.evento(plan, f"no se pudo corregir el plan: {e}")

        plan["estado"] = "pendiente_aprobacion"
        self.planes.evento(plan, "esperando aprobación del usuario (no se ha tocado la web)")
        self.notificar(plan)

    def _incorporar(self, plan, analisis, runtimes):
        cambios = analisis.pop("cambios", [])
        for i, c in enumerate(cambios, 1):
            c["n"] = i if not isinstance(c.get("n"), int) or c["n"] < 1 else c["n"]
            c.update(decision=None, decidido_por=None, decidido_en=None)
        plan["analisis"] = analisis
        plan["cambios"] = cambios
        plan["cambios_originales"] = [{k: v for k, v in c.items() if not k.startswith("decid") and k != "decision"}
                                      for c in cambios]
        objetivo = analisis.get("version_objetivo", "")
        plan["no_cubiertos"] = compatibilidad.no_cubiertos(plan["hallazgos"], objetivo)
        if plan["no_cubiertos"]:
            self.planes.evento(plan, f"AVISO: {objetivo} no corrige {len(plan['no_cubiertos'])} vulnerabilidad(es): "
                                     + ", ".join(plan["no_cubiertos"][:5]), guardar=False)
        if objetivo and objetivo != (plan.get("compatibilidad") or {}).get("version_objetivo"):
            plan["compatibilidad_objetivo"] = compatibilidad.revisar(self.v.cache, plan["componente"], objetivo, runtimes)

    # ------------------------------------------------------------------ comunicación
    def _url(self, ruta=""):
        return self.v._url(ruta)

    def notificar(self, plan):
        url = self._url(f"/plan/{plan['id']}")
        if self.bot.activo:
            tg = plan.setdefault("telegram", {})
            tg["cabecera"] = self.bot.enviar(telegram.texto_cabecera(plan, url), telegram.botones_cabecera(plan))
            tg["cambios"] = {}
            for c in plan["cambios"]:
                tg["cambios"][str(c["n"])] = self.bot.enviar(telegram.texto_cambio(plan, c),
                                                             telegram.botones_cambio(plan, c), silencioso=True)
            self.planes.guardar(plan)
        # resto de canales (consola, webhook, email): texto plano con enlace al panel
        lineas = [f"{len(plan['cambios'])} cambio(s) propuestos para {plan['componente']['nombre']} "
                  f"{plan['componente']['version']} → {(plan.get('analisis') or {}).get('version_objetivo', '?')}",
                  f"Verificación: {(plan.get('verificacion') or {}).get('estado')}"]
        for c in plan["cambios"]:
            lineas.append(f"  {c['n']}. [{c['riesgo_nivel']}] {c['titulo']} — {c['que_arregla'][:160]}")
        lineas.append("Nada se aplicará sin tu aprobación." + (f" Decide aquí: {url}" if url else ""))
        self.v.avisador.enviar(f"Propuesta de corrección ({plan['componente']['nombre']})", "\n".join(lineas),
                               canales=("consola", "webhook", "email"))

    def _refrescar_telegram(self, plan):
        tg = plan.get("telegram") or {}
        self.bot.editar(tg.get("cabecera"), telegram.texto_cabecera(plan, self._url(f"/plan/{plan['id']}")),
                        telegram.botones_cabecera(plan))
        for c in plan["cambios"]:
            self.bot.editar((tg.get("cambios") or {}).get(str(c["n"])), telegram.texto_cambio(plan, c),
                            telegram.botones_cambio(plan, c))

    # ------------------------------------------------------------------ decisiones (panel y Telegram)
    def decidir(self, plan_id, n, decision, por) -> str:
        plan, msg = self.planes.decidir(plan_id, n, decision, por)
        log.warning("Plan %s: %s (%s)", plan_id, msg, por)
        self._refrescar_telegram(plan)
        if plan["estado"] == "rechazado":
            self.bot.enviar(f"Plan de <b>{telegram.E(plan['componente']['nombre'])}</b> rechazado. "
                            "No se ha tocado nada.")
        elif not pendientes(plan) and aprobados(plan):
            self.bot.enviar(telegram.texto_resumen_decision(plan) + "\n\n¿Aplicar ahora?",
                            [[telegram.b(f"Aplicar los {len(aprobados(plan))} aprobados", "apl", plan_id),
                              telegram.b("Más tarde", "can", plan_id)]])
        return msg

    def aplicar(self, plan_id, por, en_segundo_plano=True) -> str:
        """Aplica los cambios APROBADOS. Solo se llama desde una acción explícita del usuario."""
        plan = self.planes.obtener(plan_id)
        eq = self.equipo_de(plan)
        if eq is None:
            return "El equipo de este plan ya no está registrado: no se puede aplicar."
        if eq.solo_lectura:
            return ("Este vigilante está instalado en modo solo propuestas y no puede modificar tus apps. "
                    "Para permitir aplicar cambios, ejecuta de nuevo el instalador con --permitir-aplicar.")
        try:
            Aplicador.comprobar_decisiones(plan)
        except ErrorAplicacion as e:
            return f"No se aplica: {e}"
        if not self.cerrojo_aplicar.acquire(blocking=False):
            return "Ya hay una aplicación en curso; espera a que termine."
        plan["estado"] = "aplicando"
        self.planes.evento(plan, f"aplicación ordenada por {por}", por)
        self._refrescar_telegram(plan)          # quita los botones de decisión

        def tarea():
            try:
                self._aplicar(plan_id, por)
            finally:
                self.cerrojo_aplicar.release()
        if en_segundo_plano:
            threading.Thread(target=tarea, daemon=True).start()
            return "Aplicando: te aviso al terminar."
        tarea()
        return "Hecho."

    def _aplicar(self, plan_id, por):
        plan = self.planes.obtener(plan_id)
        try:
            ap = self.equipo_de(plan).aplicar(plan, por)
        except ErrorAplicacion as e:
            plan["estado"] = "pendiente_aprobacion"
            self.planes.evento(plan, f"no se aplicó: {e}", por)
            self._refrescar_telegram(plan)          # vuelven los botones: se puede decidir otra vez
            self.bot.enviar(f"<b>No se ha aplicado nada</b> en <b>{telegram.E(plan['componente']['nombre'])}</b>: "
                            f"{telegram.E(str(e))}")
            self.v.avisador.enviar("No se aplicó la corrección", str(e), canales=("consola", "webhook", "email"))
            return
        except Exception as e:  # noqa: BLE001
            log.exception("Fallo aplicando el plan %s", plan_id)
            plan["estado"] = "fallo_aplicacion"
            self.planes.evento(plan, f"error inesperado aplicando: {e}", por)
            self.bot.enviar(f"<b>Error aplicando:</b> {telegram.E(str(e))}. Revisa el panel; hay copia de seguridad.",
                            [[telegram.b("Revertir", "rev", plan_id)]])
            return
        estados = {"aplicado": "aplicado", "revertido": "fallo_aplicacion", "fallo": "fallo_aplicacion",
                   "revertido_con_problemas": "fallo_aplicacion"}
        plan["estado"] = estados.get(ap["estado"], "fallo_aplicacion")
        self.planes.evento(plan, f"resultado de la aplicación: {ap['estado']}", por)
        self._refrescar_telegram(plan)
        texto = "\n".join(f"{'OK' if p['ok'] else ('FALLO' if p['ok'] is False else 'INFO')} · {telegram.E(p['paso'])}: "
                          f"{telegram.E(p['detalle'][:200])}" for p in ap["pasos"])
        titulo = {"aplicado": "Corrección aplicada", "revertido": "Falló la comprobación y se ha revertido",
                  "fallo": "No se pudo aplicar",
                  "revertido_con_problemas": "ATENCIÓN: se ha revertido, pero la web sigue sin responder bien"}[ap["estado"]]
        botones = [[telegram.b("Revertir", "rev", plan_id)]] if plan["estado"] == "aplicado" or \
            ap["estado"] in ("fallo", "revertido_con_problemas") else None
        self.bot.enviar(f"<b>{titulo}</b> · {telegram.E(plan['componente']['nombre'])}\n{texto}", botones)
        self.v.avisador.enviar(titulo, f"{plan['componente']['nombre']}: " +
                               "; ".join(f"{p['paso']}: {'ok' if p['ok'] else 'FALLO'}" for p in ap["pasos"]),
                               urgente=ap["estado"] != "aplicado", canales=("consola", "webhook", "email"))
        if plan["estado"] == "aplicado":
            threading.Thread(target=self.v.ciclo, args=("tras aplicar corrección",), daemon=True).start()

    def revertir(self, plan_id, por) -> str:
        plan = self.planes.obtener(plan_id)
        if not self.cerrojo_aplicar.acquire(blocking=False):
            return "Hay una aplicación en curso; espera a que termine."
        try:
            eq = self.equipo_de(plan)
            if eq is None:
                raise ErrorAplicacion("el equipo de este plan ya no está registrado")
            r = eq.revertir(plan, por)
        except ErrorAplicacion as e:
            return f"No se puede revertir: {e}"
        finally:
            self.cerrojo_aplicar.release()
        plan["estado"] = "revertido" if r["ok"] else "fallo_aplicacion"
        self.planes.evento(plan, f"revertido por {por}: {'ok' if r['ok'] else 'con problemas'} ({r['detalle']})", por)
        self.bot.enviar(f"<b>Revertido</b> {telegram.E(plan['componente']['nombre'])}: {telegram.E(r['detalle'])}")
        self.v.avisador.enviar("Corrección revertida", f"{plan['componente']['nombre']}: {r['detalle']}",
                               canales=("consola", "webhook", "email"))
        threading.Thread(target=self.v.ciclo, args=("tras revertir",), daemon=True).start()
        return "Revertido." if r["ok"] else f"Revertido con problemas: {r['detalle']}"

    # ------------------------------------------------------------------ botones de Telegram
    def _boton(self, accion, plan_id, n, quien, message_id=None) -> str:
        # --- pedir (o no) la resolución con Claude: aquí «plan_id» es el id corto del componente
        if accion == "nop":
            self.bot.editar(message_id, "Descartado. No se ha hecho nada.")
            return "Descartado"
        if accion in ("rsv", "cfs"):
            comp = self._comp_por_id(plan_id)
            if not comp:
                return "Ese componente ya no existe."
            if accion == "rsv":     # primer paso: explicar y pedir confirmación
                self.bot.editar(message_id,
                                f"<b>¿Confirmas pedir a Claude la corrección de {telegram.E(comp['nombre'])} "
                                f"{telegram.E(comp['version'])}?</b>\n\nSe enviarán a Anthropic, a través de Claude Code, las "
                                "vulnerabilidades y los ficheros de despliegue del proyecto (no los .env ni los datos). "
                                "Consume uso de tu plan de Claude. No se modificará nada hasta que apruebes cada cambio.\n\n"
                                f"<b>Consumo estimado:</b> {telegram.E(self._texto_estimacion(comp))}",
                                [[telegram.b("Sí, resolver con Claude", "cfs", plan_id), telegram.b("Cancelar", "nop", plan_id)]])
                return "Confirma para continuar"
            resultado = self.solicitar_componente(comp["clave"], quien)
            self.bot.editar(message_id, telegram.E(resultado))
            return resultado[:190]
        plan = self.planes.obtener(plan_id)
        if not plan:
            return "Ese plan ya no existe."
        nombre = telegram.E(plan["componente"]["nombre"])
        if accion == "ap":
            return self.decidir(plan_id, n, "aprobado", quien)
        if accion == "re":
            return self.decidir(plan_id, n, "rechazado", quien)
        if accion == "ret":
            return self.decidir(plan_id, None, "rechazado", quien)
        # Las acciones que tocan la web piden confirmación
        if accion == "apt":
            self.bot.enviar(f"¿Seguro? Se aprobarán y aplicarán los {len(plan['cambios'])} cambios de <b>{nombre}</b> "
                            "(con copia de seguridad previa).",
                            [[telegram.b("Sí, aprobar todo y aplicar", "cft", plan_id), telegram.b("Cancelar", "can", plan_id)]])
            return "Confirma en el mensaje nuevo"
        if accion == "apl":
            self.bot.editar(message_id, f"¿Confirmas aplicar {len(aprobados(plan))} cambio(s) en <b>{nombre}</b>?",
                            [[telegram.b("Sí, aplicar", "cfa", plan_id), telegram.b("Cancelar", "can", plan_id)]])
            return "Confirma para aplicar"
        if accion == "rev":
            self.bot.enviar(f"¿Revertir los cambios aplicados en <b>{nombre}</b>?",
                            [[telegram.b("Sí, revertir", "cfr", plan_id), telegram.b("Cancelar", "can", plan_id)]])
            return "Confirma para revertir"
        if accion in ("cft", "cfa", "cfr", "can"):
            self.bot.editar(message_id, {"cft": "Aprobado todo: aplicando…", "cfa": "Aplicando…",
                                         "cfr": "Revirtiendo…", "can": "Cancelado. No se ha tocado nada."}[accion])
            if accion == "cft":
                self.decidir(plan_id, None, "aprobado", quien)
                return self.aplicar(plan_id, quien)
            if accion == "cfa":
                return self.aplicar(plan_id, quien)
            if accion == "cfr":
                threading.Thread(target=self.revertir, args=(plan_id, quien), daemon=True).start()
                return "Revirtiendo…"
            return "Cancelado"
        return "Acción desconocida"
