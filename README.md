# eccu-manifest

Repositorio **público a propósito**. Aquí vive el manifiesto firmado de endpoints de ECCu (`production.json` y `qa.json`). La app lo descarga desde `raw.githubusercontent.com` como una de sus fuentes y **verifica la firma ella misma**: que el repo sea público no da ningún poder a quien lo lea. Quien no tenga las llaves privadas no puede publicar algo que la app acepte.

## Qué hay

| Ruta | Para qué |
|---|---|
| `production.json`, `qa.json` | Manifiesto firmado de cada ambiente. Mientras no haya uno, son un marcador `{"_note": ...}` y la Action pasa ("sin publicar"). |
| `keys/production.json`, `keys/qa.json` | Llaves **públicas** fijadas, lista `[{"keyId","publicKey"}]` (SPKI DER en base64url). Cambiarlas es cambiar de quién se fía el verificador: se revisa con lupa. |
| `scripts/verify-manifest.mjs` | Verificador sin dependencias (Node 20). Mismas reglas que `contract/manifest.md` de eccu-api. |
| `.github/workflows/verify.yml` | Corre el verificador en cada PR, en cada push a `main` y todos los días. |

## Cómo publica Miguel

1. En el repo `eccu-api`, firma con `tools/manifest` (llaves privadas en tu máquina o en tu gestor; nunca en este repo ni en ninguna Action). El primer manifiesto y los cambios graves llevan dos firmas.
2. Copia el resultado a `production.json` o `qa.json` en una rama de este repo y abre un **PR**.
3. La Action verifica firma, ambiente, vencimiento (un manifiesto nuevo ya vencido se rechaza), versión (salto máximo 50, `issuedAt` no anterior al previo) y reglas de cambio grave contra la versión anterior en git.
4. Con la Action en verde, haz merge.

**Nunca** subas llaves privadas (`.gitignore` ya excluye `*.pem` y `*.key`, pero no sustituye al cuidado). **La Action nunca firma**: solo lee.

## Renovación y avisos

Los manifiestos se publican con 30 días de vigencia y se renuevan cada 2 semanas (máximo permitido: 90 días). La corrida diaria falla si a un manifiesto le quedan menos de 7 días o ya venció; esa falla hace que GitHub te avise por correo. Es la señal para firmar y publicar uno nuevo.

Ojo: GitHub **desactiva los workflows programados tras 60 días sin actividad** en el repo. Como se renueva cada 2 semanas hay actividad de sobra, pero si pasas un tiempo sin publicar, revisa la pestaña Actions y reactiva la corrida diaria.

## Qué compara la Action (base de confianza)

- **PR**: contra la rama destino (`origin/<base>`). **Push a `main`**: contra el commit anterior al push (`github.event.before`). Si no se puede resolver esa referencia, la Action **falla** (no pasa en silencio). Solo el primer commit del repo, o una rama nueva, se tratan como "primer manifiesto" (pide 2 firmas).
- Las firmas del manifiesto nuevo se verifican con las **llaves de la base** (`keys/` de la versión anterior), no con las del PR.
- Si `keys/<ambiente>.json` cambia respecto a la base, la Action falla con **LLAVES CAMBIADAS: revisión manual** (código de salida 3). Rotar llaves es en dos pasos: (1) un PR que solo cambia `keys/` con el manifiesto igual, que Miguel revisa y funde a conciencia; (2) el manifiesto nuevo.
- Reemplazar un manifiesto real por el marcador falla.
- **Corrida diaria / manual** (`schedule`, `workflow_dispatch`): modo `daily`, sin comparar con nada ("standalone"): basta 1 firma válida de las llaves fijadas, ninguna revocada por el propio manifiesto, y que no venza en menos de 7 días. No comprueba cambios graves ni versión: eso lo hizo la corrida del PR. Un manifiesto idéntico al de la base también se verifica así.

## Límite real de confianza

En un **PR**, la Action saca `scripts/verify-manifest.mjs` de la **rama base** (`git show origin/<base>:scripts/verify-manifest.mjs`) y corre ese, con las llaves de la base: un PR no puede reescribir su propio verificador ni sus llaves. Si la base no tiene el script, falla. Además usa `--reject-expired`: un manifiesto nuevo que ya nace vencido no pasa.

Lo que **no** cubre: el archivo `.github/workflows/verify.yml` sí lo toma GitHub de la rama del PR, así que un PR puede editar el propio workflow (la Action avisa con un `::warning::` si el PR toca `scripts/` o `.github/`, pero ese aviso también vive en el workflow). Por eso la Action es una red de seguridad contra errores, no una defensa contra alguien con permiso de escribir PRs. La frontera de confianza es quién puede fundir en `main` y cómo revisa Miguel: **todo cambio en `.github/`, `scripts/` y `keys/` se revisa a mano**, además del manifiesto.

## Recomendado (cambios de ajustes de GitHub: los hace Miguel)

- **Protección de la rama `main`**: exigir PR, exigir que pase `verificar-manifiesto`, prohibir push forzado, incluir a administradores. **No exijas revisión de code owner** si eres el único dueño: GitHub no deja aprobar tu propio PR y quedarías bloqueado; con una sola cuenta basta el check de estado obligatorio. (Con revisión obligatoria hace falta una segunda cuenta.)
- Opcional, para señalar quién debe mirar las rutas sensibles, `.github/CODEOWNERS`:
  ```
  * @maular22
  ```
- Activar 2FA con llave de seguridad en la cuenta dueña y revisar quién tiene acceso de escritura (idealmente nadie más).

## Sobre el verificador

`scripts/verify-manifest.mjs` es una copia a mano de las reglas de referencia de eccu-api; una prueba de paridad en ese repo lo corre contra todos los vectores. Si cambian las reglas, se cambian los dos. Uso local:

```
node scripts/verify-manifest.mjs --environment production --previous <archivo anterior|none>
node scripts/verify-manifest.mjs --environment production --previous-ref origin/main
node scripts/verify-manifest.mjs --environment production --mode daily --min-days-left 7
```
