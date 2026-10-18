# Valutazione dipendenze e fonti

AST: selezionati binding ufficiali py-tree-sitter e grammatica JavaScript, opzionali, testati nelle versioni 0.26.0 / 0.25.0. Il parser non esegue codice; limiti 1 MiB, 50000 nodi e 1000 URL. Se l'albero è malformato non si inventano endpoint. Risoluzione di costanti/alias e template interpolati non implementata: richiede semantica di scope e test ulteriori. Documentazione: https://github.com/tree-sitter/py-tree-sitter e https://github.com/tree-sitter/tree-sitter-javascript .

Provider CT: rimangono crt.sh e CertSpotter autorizzati. Aggiunti pagine richieste/completate, provenance, disponibilità osservata e successo vuoto distinto da errore. CertSpotter documenta il cursore after; limite tre pagine resta esplicito. Riferimento: https://sslmate.com/help/reference/ct_search_api_v1 . Nessuna nuova richiesta pubblica in questa verifica.

Valutata API DNS Shodan: documenta paginazione e crediti/chiave per lookup; non integrata automaticamente senza credenziali e consenso all'invio a un terzo provider. https://developer.shodan.io/api . Nessuno scraping aggiunto. Storico rimane export locale, senza dichiarare una fonte remota operativa. Le nuove fonti non sono necessarie per eseguire le fixture loopback.
