#!/bin/bash
# Pruebas end-to-end de PhishLab
BASE=http://localhost:3123
JAR=/tmp/pl-admin.jar
JARV=/tmp/pl-visitor.jar
PASS=0
FAIL=0

check() {
  local desc="$1" expected="$2" got="$3"
  if [ "$expected" = "$got" ]; then
    echo "PASS: $desc"
    PASS=$((PASS+1))
  else
    echo "FAIL: $desc (esperado=$expected, obtenido=$got)"
    FAIL=$((FAIL+1))
  fi
}

post_json() { # url cookie csrf json
  echo "$4" | curl -s -b "$2" -X POST "$1" -H 'Content-Type: application/json' -H "x-csrf-token: $3" -d @-
}

# --- Login admin ---
LOGIN=$(curl -s -c $JAR -b $JAR -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}')
CSRF=$(echo "$LOGIN" | python -c "import sys,json;print(json.load(sys.stdin)['csrf'])")
[ -n "$CSRF" ] && check "login admin con CSRF emitido" "ok" "ok" || check "login admin con CSRF emitido" "ok" "vacio"

curl -s -b $JAR "$BASE/api/auth/me" | grep -q '"role":"admin"' && check "me: rol admin" "ok" "ok"

curl -s -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"mala"}' | grep -q "Credenciales incorrectas" && check "login erroneo rechazado" "ok" "ok"

curl -s -b $JAR -X POST "$BASE/api/pages" -H 'Content-Type: application/json' -d '{"name":"X","html":"<p>hola</p>"}' | grep -q "CSRF" && check "CSRF bloquea sin token" "ok" "ok"

# --- Crear pagina desde plantilla google-login ---
HTML=$(curl -s -b $JAR "$BASE/api/templates/google-login" | python -c "import sys,json;print(json.load(sys.stdin)['html'])")
BODY=$(python -c "import sys,json;print(json.dumps({'name':'Login Google Test','html':sys.argv[1],'templateId':'google-login'}))" "$HTML")
R=$(echo "$BODY" | curl -s -b $JAR -X POST "$BASE/api/pages" -H 'Content-Type: application/json' -H "x-csrf-token: $CSRF" -d @-)
PAGEID=$(echo "$R" | python -c "import sys,json;print(json.load(sys.stdin)['page']['id'])")
SLUG=$(echo "$R" | python -c "import sys,json;print(json.load(sys.stdin)['page']['slug'])")
[ -n "$PAGEID" ] && check "pagina creada (id=$PAGEID, slug=$SLUG)" "ok" "ok" || check "pagina creada" "ok" "error: $R"

curl -s "$BASE/p/$SLUG" | grep -q "action=\"/api/capture/$PAGEID\"" && check "action de captura inyectada en /p/:slug" "ok" "ok"

LOC=$(curl -s -o /dev/null -w "%{http_code} %{redirect_url}" -X POST "$BASE/api/capture/$PAGEID" -H 'Content-Type: application/x-www-form-urlencoded' -d "email=victima@test.com&password=Clave123")
echo "$LOC" | grep -q "^302" && check "captura responde 302" "ok" "ok"
echo "$LOC" | grep -q "accounts.google.com" && check "redireccion a google" "ok" "ok"

CAPS=$(curl -s -b $JAR "$BASE/api/captures")
echo "$CAPS" | grep -q "victima@test.com" && check "captura visible en panel" "ok" "ok"
echo "$CAPS" | grep -q "Clave123" && check "password capturada" "ok" "ok"

curl -s -b $JAR "$BASE/api/captures/export" | grep -q "victima@test.com" && check "export CSV funciona" "ok" "ok"

# --- Visitor ---
post_json "$BASE/api/users" $JAR "$CSRF" '{"username":"visitor","password":"visitor1","role":"visitor"}' | grep -q '"role":"visitor"' && check "usuario visitor creado" "ok" "ok"

CSRFV=$(curl -s -c $JARV -b $JARV -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' -d '{"username":"visitor","password":"visitor1"}' | python -c "import sys,json;print(json.load(sys.stdin)['csrf'])")
[ -n "$CSRFV" ] && check "login visitor" "ok" "ok" || check "login visitor" "ok" "vacio"

post_json "$BASE/api/pages" $JARV "$CSRFV" '{"name":"Hack","html":"<p>x</p>"}' | grep -q "Permiso denegado" && check "visitor no puede crear paginas" "ok" "ok"
curl -s -b $JARV -X DELETE "$BASE/api/pages/$PAGEID" -H "x-csrf-token: $CSRFV" | grep -q "Permiso denegado" && check "visitor no puede borrar paginas" "ok" "ok"
curl -s -b $JARV "$BASE/api/captures" | grep -q "victima@test.com" && check "visitor ve capturas" "ok" "ok"
post_json "$BASE/api/mailing" $JARV "$CSRFV" '{"email":"objetivo@test.com","name":"Objetivo"}' | grep -q '"email":"objetivo@test.com"' && check "visitor anade a lista de correos" "ok" "ok"

# --- Correo y envio simulado ---
HTMLM=$(curl -s -b $JAR "$BASE/api/templates/google-email" | python -c "import sys,json;print(json.load(sys.stdin)['html'])")
BODYM=$(python -c "import sys,json;print(json.dumps({'name':'Alerta Test','subject':'Alerta de seguridad en tu cuenta','html':sys.argv[1],'templateId':'google-email'}))" "$HTMLM")
EMAILID=$(echo "$BODYM" | curl -s -b $JAR -X POST "$BASE/api/emails" -H 'Content-Type: application/json' -H "x-csrf-token: $CSRF" -d @- | python -c "import sys,json;print(json.load(sys.stdin)['email']['id'])")
[ -n "$EMAILID" ] && check "correo creado (id=$EMAILID)" "ok" "ok" || check "correo creado" "ok" "error"

SEND=$(echo "{\"pageId\":\"$PAGEID\"}" | curl -s -b $JAR -X POST "$BASE/api/emails/$EMAILID/send" -H 'Content-Type: application/json' -H "x-csrf-token: $CSRF" -d @-)
echo "$SEND" | grep -q '"simulado":true' && check "envio simulado sin SMTP" "ok" "ok"
curl -s -b $JAR "$BASE/api/mail-log" | grep -q "objetivo@test.com" && check "mail-log registra envio" "ok" "ok"

# --- Ajustes ---
echo '{"theme":"medianoche","simBanner":true}' | curl -s -b $JAR -X PUT "$BASE/api/settings" -H 'Content-Type: application/json' -H "x-csrf-token: $CSRF" -d @- | grep -q '"theme":"medianoche"' && check "tema medianoche guardado" "ok" "ok"
curl -s "$BASE/p/$SLUG" | grep -q "SIMULACION DE PHISHING" && check "banner de simulacion visible" "ok" "ok"
echo '{"theme":"claro"}' | curl -s -b $JARV -X PUT "$BASE/api/settings" -H 'Content-Type: application/json' -H "x-csrf-token: $CSRFV" -d @- | grep -q "Permiso denegado" && check "visitor no cambia ajustes" "ok" "ok"

# --- Subida de imagen ---
printf 'PNGDATA' > /tmp/pl-test.png
curl -s -b $JAR -X POST "$BASE/api/uploads" -H "x-csrf-token: $CSRF" -F "file=@/tmp/pl-test.png" | grep -q '"/uploads/' && check "subida de imagen OK" "ok" "ok"

# --- Panico ---
echo '{"confirm":"BORRAR"}' | curl -s -b $JAR -X POST "$BASE/api/panic" -H 'Content-Type: application/json' -H "x-csrf-token: $CSRF" -d @- | grep -q '"ok":true' && check "panico ejecutado" "ok" "ok"
curl -s -b $JAR "$BASE/api/captures" | grep -q "victima@test.com" && check "capturas borradas tras panico" "FAIL" || check "capturas borradas tras panico" "ok" "ok"
curl -s -b $JAR "$BASE/api/pages" | grep -q "Login Google Test" && check "paginas borradas tras panico" "FAIL" || check "paginas borradas tras panico" "ok" "ok"
curl -s -b $JAR "$BASE/api/mailing" | grep -q "objetivo" && check "lista borrada tras panico" "FAIL" || check "lista borrada tras panico" "ok" "ok"
curl -s -b $JAR "$BASE/api/auth/me" | grep -q '"role":"admin"' && check "admin conservado tras panico" "ok" "ok"

# --- Factory reset ---
echo '{"confirm":"RESETEAR"}' | curl -s -b $JAR -X POST "$BASE/api/factory-reset" -H 'Content-Type: application/json' -H "x-csrf-token: $CSRF" -d @- | grep -q '"ok":true' && check "factory reset ejecutado" "ok" "ok"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -b $JAR "$BASE/api/auth/me")
check "sesion destruida tras factory reset (401)" "401" "$CODE"

# --- Nuevo login tras reset con admin/admin ---
curl -s -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}' | grep -q '"role":"admin"' && check "admin/admin funciona tras reset" "ok" "ok"

echo ""
echo "=== RESUMEN: $PASS OK, $FAIL FAIL ==="
exit $FAIL
