# Documentation — migration_schema.sh

## Objectif

`migration_schema.sh` automatise une migration (ou un rafraîchissement) de schémas Safirh depuis une base Oracle 11g vers une base Oracle 19c hébergée dans un PDB, en s’appuyant sur Data Pump (expdp/impdp) et SQL*Plus. Le script est interactif : il guide l’opérateur dans le choix des schémas, des dumps et des étapes à exécuter. 【F:migration_schema.sh†L1-L2】【F:migration_schema.sh†L5330-L5440】

## Ce que le script ne fait pas

Le script indique explicitement qu’il ne prend **pas** en charge :

- l’évaluation de l’espace disque sur le serveur 19c ;
- la création du PDB ;
- la création des tablespaces sur la destination. 【F:migration_schema.sh†L1-L7】

## Ce que le script fait (vue d’ensemble)

À haut niveau, le script :

- propose un **mode d’exécution** (migration simple ou rafraîchissement) ;【F:migration_schema.sh†L337-L369】【F:migration_schema.sh†L5386-L5419】
- collecte des **crédentiels DBA** (via un fichier chiffré ou saisie interactive) et valide l’accès ;【F:migration_schema.sh†L403-L559】
- vérifie la disponibilité de l’instance et la configuration Data Pump ;【F:migration_schema.sh†L1690-L1774】【F:migration_schema.sh†L5404-L5419】
- guide la **sélection des schémas** applicatifs, utilitaires et autres, puis la sélection des **dumps** à exporter/importer ;【F:migration_schema.sh†L1834-L1966】【F:migration_schema.sh†L5190-L5324】
- exécute les **étapes sélectionnées** (expdp/impdp, SQL post-traitement, paramétrage, etc.) et produit un **récapitulatif d’exécution** ;【F:migration_schema.sh†L1761-L1852】【F:migration_schema.sh†L5330-L5440】
- journalise l’ensemble dans un **fichier de log** et prépare un mail HTML de synthèse. 【F:migration_schema.sh†L33-L113】

## Modes d’exécution

Le script propose deux modes (choix interactif) :【F:migration_schema.sh†L337-L369】

1. **Migration simple** d’un schéma 11g vers 19c. 【F:migration_schema.sh†L337-L369】
2. **Rafraîchissement** d’un environnement de test 19c avec le dernier dump d’une production 11g (copie + migration). 【F:migration_schema.sh†L337-L369】

Le mode influence la sélection des dumps et les étapes suivantes (par exemple, en mode 2, le dump est choisi sur l’hôte 11g de production). 【F:migration_schema.sh†L5416-L5423】

## Paramètres obligatoires

Le script attend **trois paramètres** au lancement :【F:migration_schema.sh†L5359-L5394】

```bash
./migration_schema.sh <ORACLE_SID> <ORACLE_PDB_SID> <ALIAS_DB_SRC>
```

- `ORACLE_SID` : instance 19c cible (utilisée par `oraenv`).【F:migration_schema.sh†L5371-L5386】
- `ORACLE_PDB_SID` : PDB cible dans lequel s’effectue la migration. 【F:migration_schema.sh†L5371-L5378】
- `ALIAS_DB_SRC` : alias de connexion vers la base 11g source. 【F:migration_schema.sh†L5388-L5392】

Si ces paramètres manquent, le script s’arrête. 【F:migration_schema.sh†L352-388】【F:migration_schema.sh†L5359-L5375】

## Prérequis techniques

### Outils et utilitaires

Le script s’appuie sur :

- **SQL*Plus** (`sqlplus`) pour les opérations SQL et PL/SQL ;【F:migration_schema.sh†L5391-L5392】
- **Data Pump** (`expdp`/`impdp`) pour l’export et l’import ;【F:migration_schema.sh†L2103-L2308】【F:migration_schema.sh†L3098-L4168】
- **SSH** (accès sans mot de passe) pour exécuter les exports sur le serveur 11g et accéder aux dumps ;【F:migration_schema.sh†L2124-L2148】【F:migration_schema.sh†L5190-L5324】
- **GPG** ou **OpenSSL** si vous utilisez des fichiers de crédentiels chiffrés. 【F:migration_schema.sh†L417-L507】

### Variables et fichiers attendus

Le script s’attend à trouver (ou à créer) les éléments suivants autour de son emplacement :【F:migration_schema.sh†L5330-L5394】

- `conf/info_mail.conf` : configuration mail (expéditeur, destinataire).【F:migration_schema.sh†L5350-L5352】
- `conf/info_cnx_bd_${ORACLE_SID}.conf` : configuration de connexion/paramètres liés à l’instance. 【F:migration_schema.sh†L5391-L5396】
- répertoires `sql/`, `par/`, `tmp/`, `log/` pour scripts SQL, parfiles Data Pump, temporaires et journaux. 【F:migration_schema.sh†L5330-L5342】

> ⚠️ Ces fichiers/répertoires doivent exister et contenir les paramètres attendus par le script.

### Crédentiels DBA

Le script peut lire des crédentiels DBA depuis un fichier chiffré `${d_cmd}/${user}.cred` (GPG ou OpenSSL), sinon il bascule en **saisie interactive**. 【F:migration_schema.sh†L403-L559】

## Journalisation et rapport d’exécution

- Chaque exécution produit un **fichier de log** (dans `log/`), incluant les sorties SQL et Data Pump. 【F:migration_schema.sh†L66-L113】【F:migration_schema.sh†L5330-L5369】
- Un **récapitulatif des étapes** est disponible en fin de script (statut, RC, durée). 【F:migration_schema.sh†L300-L336】
- Un email HTML peut être préparé via `conf/info_mail.conf` (l’envoi est commenté par défaut). 【F:migration_schema.sh†L33-L113】

## Exemples d’utilisation

### Migration simple

```bash
./migration_schema.sh ORCL19C PDB_TEST ALIAS_11G
```

### Rafraîchissement d’un environnement de test

```bash
./migration_schema.sh ORCL19C PDB_TEST ALIAS_11G
```

> Dans les deux cas, le **mode est choisi** dans l’interface interactive au démarrage. 【F:migration_schema.sh†L337-L369】

## Dépannage rapide

- **Pas de paramètres** : relancer avec `ORACLE_SID`, `ORACLE_PDB_SID`, `ALIAS_DB_SRC`. 【F:migration_schema.sh†L5359-L5394】
- **Problème d’accès 11g** : vérifier l’alias `ALIAS_DB_SRC`, les crédentiels et la connectivité. 【F:migration_schema.sh†L514-L559】
- **SSH non fonctionnel** : configurer l’accès sans mot de passe vers l’hôte 11g utilisé pour les exports. 【F:migration_schema.sh†L2124-L2148】

---

*Document créé pour servir de guide opératoire du script `migration_schema.sh`.*
