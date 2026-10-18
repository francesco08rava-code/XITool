# Provider CT e DNS

Stati: SUCCESS, SUCCESS_EMPTY, PARTIAL, RATE_LIMITED, TIMEOUT, FAILED, DISABLED; legacy_status conservato. Registrati durata, tentativi, conteggi, duplicati concreti, pagine richieste/completate, errori/categoria e timestamp. Wildcard CT e seed separati. ct_providers può disabilitare fonti senza traffico; valore predefinito crtsh/certspotter.

Fixture coprono successo/vuoto, duplicati, normalizzazione, formati malformati, 429/500, prima pagina preservata su errore, paginazione/cursore e redirect provider fuori scope respinto. Otto test PassiveTests esistenti più cinque ProviderStatesTests. I controlli HTTP comuni verificano retry/cancellazione; un provider interrotto resta riprendibile al livello del task, non della singola pagina: GET già letti possono ripetersi.

DNS UDP reale: A/AAAA/CNAME/TTL, NXDOMAIN, SERVFAIL, wildcard, nuovo hostname e CNAME esterno mai interrogato. Scope/IDNA/deny/peer conservati. Il DNS di laboratorio non è una misura di affidabilità di resolver pubblici.

| Live provider | Stato | Pagine | Nomi unici | Categoria errore |
|---|---|---:|---:|---|
| crtsh | TIMEOUT | 0 | 0 | NETWORK_TIMEOUT |
| certspotter | SUCCESS | 2 | 2 | None |

Live limitato ai provider autorizzati cercando example.com; nessuna risoluzione/probe HTTP del dominio cercato. CertSpotter effettivamente raggiunto; crt.sh TIMEOUT in questo ambiente non significa indisponibilità globale. Ulteriori dettagli in V52_PROVIDER_LIVE.json. Ripetizione esplicita: python benchmarks/verify_providers.py --live --root example.com.

CertSpotter: endpoint/paginazione documentati https://sslmate.com/help/reference/ct_search_api_v1 . crt.sh usa la comune interfaccia JSON q/output, non viene attribuito uno SLA o una disponibilità live non osservata. Valutata API DNS Shodan https://developer.shodan.io/api : richiede chiave/crediti non disponibili, quindi non aggiunta automaticamente. Nessuno scraping aggiunto. CertSpotter autenticato resta opzionale tramite riferimento env esistente.
