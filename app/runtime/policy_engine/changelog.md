# Changelog

À chaque changement de règle non-trivial, tu bumps version dans rules.json et ajoutes une entrée au changelog — ça donne une vraie traçabilité pour la soutenance ("pourquoi cette règle a changé, quand, pour quelle raison sécurité").

## [1.0.0] - 2026-08-XX
### Added
- Règles initiales : lecture user_uploads (allow), écriture /etc (deny),
  outil calculator (allow), outil shell_exec (deny),
  API weather (allow), réseau sortant vers provider LLM (allow)


## [1.1.0] - 2026-08-13
### Added
- Règle `allow-llm-ask-authenticated` (resource: llm, action: ask) — nécessaire pour brancher
  le Policy Engine sur `runtime.ask()` sans bloquer tout le monde par fail-closed
- Validation stricte des règles au chargement (`PolicyEngine._validate_rules()`) : `effect`
  invalide ou clé de `conditions` inconnue lève désormais une erreur explicite au démarrage,
  au lieu d'être ignorée silencieusement

### Changed
- `required_scopes` réellement exploité dans `_conditions_match()` (auparavant présent dans
  le schéma mais jamais vérifié)
- Règle `allow-read-user-uploads` : ajout de la condition `required_scopes: ["file:read"]`

### Fixed
- Un typo dans `effect` (ex. "denny" au lieu de "deny") pouvait auparavant transformer un
  refus en autorisation silencieuse — bloqué désormais par la validation au chargement


## [1.2.0] - 2026-08-16
### Fixed
- max_file_size_mb comparait la taille contre le subject au lieu de la resource
### Added
- allow-write-user-uploads (aucune règle d'écriture légitime n'existait avant)
- allow-network-weather-api (Network Manager n'avait pas de règle pour ce domaine)
### Changed
- KNOWN_MATCH_KEYS accepte désormais "port" et "domain"

