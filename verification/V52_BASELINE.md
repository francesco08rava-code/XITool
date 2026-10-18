# Baseline V5.2

Versione iniziale 5.1.0a1, Python 3.12.14, Windows 11. Base Git c7bb4706910037b994800fc1104594e38aa94e61, checkout V3/V4/V5/V5.1 non committato conservato; nessun reset/clean/stage/commit/push. Il manifest V51 coincide in tutti i 56 file: V52_SOURCE_BEFORE.json. Sorgenti V5.1 copiati prima delle modifiche nell'area di lavoro v51-source-snapshot.

Baseline suite completa con Chrome, AST e DNS: 303 test, 300 superati, 3 saltati, zero fallimenti/errori. Durata e log integrali in V52_BASELINE_TESTS.txt. Skip: Bash/POSIX installer (2) e symlink Windows (1). Dipendenze PyYAML 6.0.3, dnspython 2.9.0, Playwright 1.64.0, tree-sitter 0.26.0, grammatica JS 0.25.0.

Problemi riproducibili/da misurare: 7 sole fixture nel dataset V51; manca un laboratorio unico; coda statica JS può diventare visita HTTP; moltiplicazione del rallentamento per errori concorrenti; status provider non separa RATE_LIMITED/TIMEOUT/SUCCESS_EMPTY; alias/costanti JS non risolti. Si preservano verifiche IP/peer/TLS/redirect e gate di conferma.

Ordine: laboratorio e matrice 13 moduli → CT/DNS → AST/input → accuratezza per contratto → timeout/tassonomia → launcher/Kali → suite e benchmark identici V51/V52 → rapporto. Nessun servizio pubblico usato come bersaglio; egress facoltativo limitato ai provider CT autorizzati per example.com, senza probing HTTP del dominio.
