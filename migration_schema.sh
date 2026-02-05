#!/bin/bash
# Script utiliser pour migrer une base Safirh 11g à 19c dans un PDB
# Ce que le script ne fait pas:
#   - Évaluation de l'espace disque sur le serveur 19c
#   - Création du PDB
#   - Création des tablespaces sur la destination
# Ce qu'il fait:
#   - Liste les schémas Safirh sur la BD 11g et demande d'en choisir 1 ou aucun
#   - Liste les schémas utilitaires et demande d'en choisir 1 ou plus ou aucun
#   - Liste les schémas autres et demande d'en choisir 1 ou plus ou aucun
#   - 
#   - 
 
# Modifications
# 2025-11-24 12:00  C. Lize   Ajout sauvegarde et restore des tables de paramètres     
# 2025-11-25 16:08  C. Lize   Ajout option flashback_time dans les expdp pour que l'export soit     
# 2025-12-04 10:41  C. Lize   Ajout mise à jour date de refresh 11G     

# --- Stockage des résultats d'étapes ---
# step_num -> valeurs
declare -Ag STEP_RCS STEP_FUNCS_R STEP_LABELS_R STEP_DURS STEP_IGNORED STEP_STATUS

####### Functions
function SendHTMLMail(){
        if [ ${statut} -eq ${SUCCES} ]; then
            statut_text='* OK *'
        else
            statut_text='* ERREUR *'
        fi
        sed -i "s/SubjectARemplacer/Subject\:${statut_text} \: Migration/g" ${f_log}
        #cat ${f_log} | /usr/sbin/sendmail $mailto
}

function HTMLHeader(){
    echo "From: ${mailfrom}" > ${f_log}
    echo "To: ${mailto}" >> ${f_log}
    echo 'MIME-Version: 1.0' >> ${f_log}
    echo 'SubjectARemplacer' >> ${f_log}
    echo 'Content-Type: text/html' >> ${f_log}
    echo 'Content-Disposition: inline' >> ${f_log}
    echo '<html>' >> ${f_log}
    echo '<head>' >> ${f_log}
    echo "<title>Migration 19c de ${schema_name} </title>" >> ${f_log}
    echo '</head>' >> ${f_log}
    echo '<body>' >> ${f_log}
    echo '<style type="text/css">' >> ${f_log}
    echo 'pre' >> ${f_log}
    echo '{' >> ${f_log}
    echo 'font-family:courier, "courier new", monospace;' >> ${f_log}
    echo 'font-size:1em;' >> ${f_log}
    echo 'color:#000;' >> ${f_log}
    echo 'background-color:#fff;' >> ${f_log}
    echo '}' >> ${f_log}
    echo '</style>' >> ${f_log}
    echo '<pre>' >> ${f_log}
}

function HTMLFooter(){
        echo '</pre>' >> ${f_log}
        echo '</body>' >> ${f_log}
        echo '</html>' >> ${f_log}
}

function echoT(){
    # Affiche à l'écran (avec couleurs si présentes)
    local txt="$1"
    echo "${txt}"

    # Nettoyage ANSI pour le fichier de log
    # 1) retire les séquences CSI complètes : ESC[ ... lettre
    # 2) retire les résidus SGR typiques (ex: 33m, 0m, 38;5;153m) si ESC a été perdu
    local txt_log
    txt_log="$(printf '%s' "${txt}" | sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g;
        s/(^|[^0-9])((0|1|2|3|4|5|7|8|9|3[0-7]|4[0-7]|9[0-7]|10[0-7]|38;5;[0-9]{1,3}|48;5;[0-9]{1,3})(;((0|1|2|3|4|5|7|8|9|3[0-7]|4[0-7]|9[0-7]|10[0-7]|38;5;[0-9]{1,3}|48;5;[0-9]{1,3}))*)?)m/\\1/g')"

    echo "$(date '+%Y-%m-%d %H:%M:%S') : ${txt_log}" >> "${f_log}"
}


# Affiche un message de statut: 0: OK 1: ERREUR 2: ATTENTION
function msg_status() {

    local _type=$1
    local _msg=$2

    if [ ${_type} -eq 0 ]; then
        echoT "**************"
        echoT "***   ${GREEN}OK${RESET}   *** ${_msg}"
        echoT "**************"
    elif [ ${_type} -eq 1 ]; then
        echoT "**************"
        echoT "*** ${RED}ERREUR${RESET} *** ${_msg}"
        echoT "**************"
    else
        echoT "******************"
        echoT "*** ${YELLOW}ATTENTION${RESET} *** ${_msg}"
        echoT "******************"
    fi
}

function err_manque_parametre(){
    HTMLHeader
    echoT "**********"
    echoT "*  INFO  * Execution sur le serveur  ${HOSTNAME} par ${USERNAME} le  `date +%Y%m%d" "%H%M%S`"
    echoT "**********"
    msg_status 1 "Parametre SID et/ou PDB  non fourni au fichier de commandes, impossible de continuer!"
    statut=99
    fin
}

function pas_de_fichier_config(){
    HTMLHeader
    echoT "**********"
    echoT "*  INFO  * Execution sur le serveur  ${HOSTNAME} par ${USERNAME} le  `date +%Y%m%d" "%H%M%S`"
    echoT "**********"
    msg_status 1 "Le fichier de configuration ${f_conf} n'existe pas!"
    statut=98
    fin
 }

function fin(){
    echoT "Fichier de log : ${f_log}"
    echoT "Fin du Script : `date +%Y%m%d" "%H%M%S` Statut: $statut"
    HTMLFooter
    SendHTMLMail
    exit ${statut}
}

function boite_titre() {
    # Fonction qui ecrit une phrase centree, eventuellement sur plusieurs lignes a l'interieur d'un cadre en etoiles
    # Le parametre passe a la fonction contient la phrase que l'on veut mettre dans le frame
    # Pour que la phrase soit sur plusieurs lignes, il faut separer chaque morceau de la phrase par le symbole pipe: |
    local input="$1"
    IFS='|' read -ra ADDR <<< "$input" # Split string into array

    local total_len=100 # Total frame width
    local border_stars="***" # 3 stars on each side
    local border_len=${#border_stars}

    # Couleurs/styles
    local BOLD=$'\e[1m'
    local BLUE=$'\e[34m'
    local RESET=$'\e[0m'

    # Print top frame
    for ((i=1; i<=total_len; i++)); do echo -n "*"; done
    echo

    # Print each string centered
    for i in "${ADDR[@]}"; do
        local len=${#i}
        local padding=$((total_len - 2 * border_len - len)) # Total padding space
        local left_padding=$((padding / 2))
        local right_padding=$((padding - left_padding))

        printf "%s" "$border_stars"
        printf '%*s' "$left_padding" ""
        # texte en bold + bleu, puis reset avant les espaces et la bordure
        printf "%s%s%s" "${BOLD}${BLUE}" "$i" "${RESET}"
        printf '%*s' "$right_padding" ""
        printf "%s\n" "$border_stars"
    done

    # Print bottom frame
    for ((i=1; i<=total_len; i++)); do echo -n "*"; done
    echo
}

function boite_soustitre() {
    # Fonction qui ecrit une phrase centree, eventuellement sur plusieurs lignes a l'interieur d'un cadre en points
    # Le parametre passe a la fonction contient la phrase que l'on veut mettre dans le frame
    # Pour que la phrase soit sur plusieurs lignes, il faut separer chaque morceau de la phrase par le symbole pipe: |
    local input="$1"
    IFS='|' read -ra ADDR <<< "$input" # Split string into array

    local total_len=94 # Largeur totale du cadre (même que boite_titre)
    local border_char='-'
    local border="${border_char}${border_char}${border_char}" # 3 points de chaque côté
    local border_len=${#border}

    # Couleurs/styles
    local RESET=$'\e[0m'
    local COLOR=${CLEARBLUE}

    # Imprime le cadre supérieur avec 3 espaces avant et après
    printf "   "
    for ((i=1; i<=total_len; i++)); do echo -n "${border_char}"; done
    echo "   "

    # Imprime chaque ligne centrée
    for i in "${ADDR[@]}"; do
        local len=${#i}
        local padding=$((total_len - 2 * border_len - len))
        local left_padding=$((padding / 2))
        local right_padding=$((padding - left_padding))

        printf "   " # 3 espaces avant le cadre
        printf "%s" "$border"
        printf '%*s' "$left_padding" ""
        printf "%s%s%s" "${COLOR}" "$i" "${RESET}"
        printf '%*s' "$right_padding" ""
        printf "%s" "$border"
        echo "   " # 3 espaces après le cadre
    done

    # Imprime le cadre inférieur avec 3 espaces avant et après
    printf "   "
    for ((i=1; i<=total_len; i++)); do echo -n ${border_char}; done
    echo "   "
}

function Question_YesNo(){
    #Texte de la question
    local __question="$1"
    # nom de la variable globale qui recoit le resultat
    local __resultvar="$2"
    local __answer='Z'

    while true; do
        read -p "${__question}(O/N)" yn
        case ${yn} in
            [Oo]* ) __answer='Y'; break;;
            [Nn]* ) __answer='N'; break;;
            * ) echo "Repondre par 'O' ou 'N'.";;
        esac
    done

    # Retourne la valeur
    if [[ "${__resultvar}" ]]; then
        # Si la variable __resultvar n'est pas vide alors son contenu
        # devient le nom de la variable dans laquelle on veut retourner __answer
        # Comportement d'une  procedure
        eval ${__resultvar}="'$__answer'"
    else
        # Retourne le resultat 
        # Comportement en mode fonction
        echo "${__answer}"
    fi

}

function Question_Number(){
    # Texte de la question
    local __question="$1"
    # Liste autorisée (ex: "1,3,5")
    local __allowed_list="$2"
    # Nom de la variable globale qui reçoit le résultat
    local __resultvar="$3"
    local __answer=''

    # Transformer la liste en tableau pour validation facile
    IFS=',' read -r -a allowed_array <<< "$__allowed_list"

    while true; do
        read -p "${__question} [${__allowed_list}] : " user_input

        # Vérifier si l'entrée correspond à un élément autorisé
        local valid=false
        for num in "${allowed_array[@]}"; do
            if [[ "$user_input" == "$num" ]]; then
                valid=true
                break
            fi
        done

        if [[ "$valid" == true ]]; then
            __answer="$user_input"
            break
        else
            echo "Entrée invalide. Chiffres autorisés : ${__allowed_list}"
        fi
    done

    # Retourne la valeur
    if [[ -n "$__resultvar" ]]; then
        eval ${__resultvar}="'$__answer'"
    else
        echo "${__answer}"
    fi
}

function continue_execution(){

    local __question="$1"

    local __result=$(Question_YesNo "${__question}")

    if [ "${__result}" = "Y" ] ; then
        echoT " "
        echoT "*** ${GREEN}OK${RESET} *** Poursuite du processus de migration a `date +%Y%m%d_%H%M%S`"
        echoT " "
    else
        echoT " "
        echoT "*** ${GREEN}OK${RESET} *** Interruption volontaire du processus de migration a `date +%Y%m%d_%H%M%S`"
        echoT " "
        statut=1
        fin
    fi

}

# analyse_rslt :
# - ne stoppe jamais
# - enregistre: numero d'etape, fonction, rc, ignore, durée, status
#
# Supporte 2 signatures pour compatibilité:
#   (A) ancienne: analyse_rslt <fn> <rc> <ignore>
#   (B) nouvelle: analyse_rslt <step_num> <fn> <rc> <ignore> [label] [dur_s]
function analyse_rslt() {
    local step fn rc ignore label dur

    # Détection signature
    if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
        step="$1"; fn="$2"; rc="$3"; ignore="$4"; label="${5:-$2}"; dur="${6:-}"
    else
        # ancienne signature : pas de step connu
        step="${CURRENT_STEP:-0}"
        fn="$1"; rc="$2"; ignore="$3"
        label="${CURRENT_LABEL:-$fn}"
        dur="${CURRENT_DUR:-}"
    fi

    # Normalisation
    step="${step:-0}"
    rc="${rc:-1}"
    ignore="${ignore:-0}"

    local status
    if (( rc == 0 )); then
        status="OK"
    else
        if (( ignore == 1 )); then
            status="IGNORED"
        else
            status="ERREUR"
        fi
    fi

    # Enregistre
    STEP_RCS["$step"]="$rc"
    STEP_FUNCS_R["$step"]="$fn"
    STEP_LABELS_R["$step"]="$label"
    STEP_DURS["$step"]="${dur:-}"
    STEP_IGNORED["$step"]="$ignore"
    STEP_STATUS["$step"]="$status"

    # Affichage non-interactif
    printf -v _sn "%2d" "$step" 2>/dev/null || _sn="$step"
    if [[ "$status" == "OK" ]]; then
        msg_status 0 "[etape ${_sn}]: ${fn} (rc=${rc})"
    elif [[ "$status" == "IGNORED" ]]; then
        msg_status 2 "[etape ${_sn}]: ${fn} (rc=${rc}) -> erreur ignorée"
    else
        msg_status 1 "[etape ${_sn}]: ${fn} (rc=${rc})"
        # On ne stoppe plus ici. On garde juste un statut global non-zero.
        (( statut == 0 )) && statut="$rc"
    fi
}

# Affiche le récapitulatif de toutes les étapes exécutées
function print_steps_report() {
    boite_titre "Récapitulatif des étapes"

    mapfile -t steps_sorted < <(printf "%s\n" "${!STEP_STATUS[@]}" | sort -n)

    echoT ""
    echoT "  STEP  STATUS    RC   DURATION  FUNCTION"
    echoT "  ----  --------  ---  --------  -------------------------------"

    local s st rc dur fn line
    for s in "${steps_sorted[@]}"; do
        # sécurité : ignore toute clé vide / non numérique / 0
        [[ -n "$s" && "$s" =~ ^[0-9]+$ ]] || continue
        (( s == 0 )) && continue

        st="${STEP_STATUS[$s]:-?}"
        rc="${STEP_RCS[$s]:-?}"
        dur="${STEP_DURS[$s]:--}"
        fn="${STEP_FUNCS_R[$s]:-?}"

        printf -v line "  %4d  %-8s  %3s  %8s  %s" "$s" "$st" "$rc" "$dur" "$fn"
        echoT "$line"
    done

    echoT ""
    if (( statut == 0 )); then
        echoT "Statut global: OK"
    else
        echoT "Statut global: ECHEC (statut=${statut})"
    fi
}

function choix_mode_script(){

    boite_titre "Choix du mode de fonctionnement du script"
    echoT " "
    echoT "Deux possibilités:"
    echoT "  1 - Migration simple d'un schéma 11g vers un schéma 19c"
    echoT "  2 - Rafraîchissement d'un env. de test 19c avec le dernier dump d'une prod 11g (copie + migration)"
    echoT " "

    local _mode
    _mode=$(Question_Number "Quel mode choisissez-vous ?" "1,2")

    # Variable globale (ou export) pour réutilisation dans la suite du script
    mode_script="${_mode}"
    export mode_script

    if [[ "${mode_script}" = "1" ]]; then
        echoT "Mode sélectionné: 1 - Migration simple 11g -> 19c"
    else
        echoT "Mode sélectionné: 2 - Rafraîchissement env. test 19c (copie + migration depuis prod 11g)"
    fi
}

# Demande et valide les credentials DBA
# Si ${d_cmd}/${user_tty}.cred existe, tente de le déchiffrer (gpg puis openssl)
# Résultat : variables globales db_user db_user_pwd db_user19c db_user19c_pwd
function ask_dba_credentials() {

    # Détecte l'utilisateur qui a initié la session TTY
    user_tty="$(who am i 2>/dev/null | awk '{print $1}')"
    # fallback si who am i ne renvoie rien (ex: exécution via cron/sudo)
    user_tty="${user_tty:-${SUDO_USER:-$(logname 2>/dev/null)}}"
    user_tty="${user_tty:-unknown}"

    cred_file="${d_cmd}/${user_tty}.cred"

    if [[ -f "${cred_file}" ]]; then
        boite_titre "Fichier de crédentiels trouvé: ${cred_file}"
        echoT "Un fichier de crédentiels chiffré a été trouvé pour l'utilisateur ${user_tty}."
        # demande du mot de passe pour déchiffrer
        read -s -r -p "Entrez le mot de passe pour déchiffrer ${cred_file}: " cred_pass
        echo

        # Prépare un fichier temporaire pour la version déchiffrée
        tmp_cred="$(mktemp /tmp/${user_tty}.cred.XXXXXX)" || { echoT "${RED}ERREUR${RESET} : mktemp a échoué"; return 1; }
        # APRÈS  (one-shot, s’exécute à chaque RETURN de la fonction, puis se retire)
        trap 'trap - RETURN; \
              if [[ -n "${tmp_cred:-}" && -f "${tmp_cred}" ]]; then \
                 shred -u "${tmp_cred}" 2>/dev/null || rm -f "${tmp_cred}"; \
              fi; \
            unset cred_pass' RETURN
        
        decrypted_ok=0

        # 1) Essaye gpg (fichier chiffré avec gpg -c)
        if command -v gpg >/dev/null 2>&1; then
            if printf "%s" "${cred_pass}" | gpg --batch --quiet --yes --pinentry-mode loopback --passphrase-fd 0 --decrypt "${cred_file}" > "${tmp_cred}" 2>/dev/null; then
                decrypted_ok=1
                echoT "Décryptage avec gpg : OK"
            fi
        fi

        # 2) Si gpg a échoué, essai openssl (AES-256-CBC PBKDF2)
        if [[ "${decrypted_ok}" -eq 0 ]] && command -v openssl >/dev/null 2>&1; then
            if openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -in "${cred_file}" -out "${tmp_cred}" -pass pass:"${cred_pass}" 2>/dev/null; then
                decrypted_ok=1
                echoT "Décryptage avec openssl : OK"
            fi
        fi

        if [[ "${decrypted_ok}" -eq 1 ]]; then
            set -o allexport
            # shellcheck disable=SC1090
            . "${tmp_cred}" 2>/dev/null || true
            set +o allexport
            
            if [[ -z "${db_user:-}" || -z "${db_user_pwd:-}" || -z "${db_user19c:-}" || -z "${db_user19c_pwd:-}" ]]; then
                echoT "**************"
                echoT "*** ${YELLOW}ATTENTION${RESET} *** Le fichier déchiffré ne contient pas toutes les variables requises."
                echoT "Variables trouvées:"
                echoT "  db_user='${db_user:-<absent>}'"
                echoT "  db_user19c='${db_user19c:-<absent>}'"
                echoT "**************"
                echoT "Je passe en mode saisie interactive."
                unset db_user db_user_pwd db_user19c db_user19c_pwd
            else
                echoT "${GREEN}OK${RESET} : credentials chargés depuis ${cred_file}."
                
                db11g_name=$(${SQLPLUS} -L -S /nolog <<SQL | sed 's/^[[:space:]]*//; s/[[:space:]]*$//;/^$/d'
set heading off feedback off pages 0 verify off echo off trimout on trimspool on
connect ${db_user}/${db_user_pwd}@${alias_db_src}
select instance_name from sys.v_\$instance ;
SQL
)
                _rc=$?

                if [[ $_rc -ne 0 ]]; then
                    msg_status 1 "Connexion SQL*Plus échouée (code=$_rc). Vérifie db_user/db_user_pwd/alias_db_src."
                    unset db_user db_user_pwd db_user19c db_user19c_pwd db11g_name
                else
                    host11g_name=$(${SQLPLUS} -L -S /nolog <<SQL | sed 's/^[[:space:]]*//; s/[[:space:]]*$//;/^$/d'
set heading off feedback off pages 0 verify off echo off trimout on trimspool on
connect ${db_user}/${db_user_pwd}@${alias_db_src}
select host_name from sys.v_\$instance ;
SQL
)

                    return 0
                fi
            fi
        else
            msg_status  2 "Échec du décryptage de ${cred_file} (gpg/openssl)."
            unset db_user db_user_pwd db_user19c db_user19c_pwd
        fi

        if [[ -n "${tmp_cred:-}" && -f "${tmp_cred}" ]]; then
            shred -u "${tmp_cred}" 2>/dev/null || rm -f "${tmp_cred}"
        fi
        unset cred_pass
        # On bascule en mode interactif
    fi

    # -------------------------------------------------------
    # Mode interactif : demande manuelle des creds
    # -------------------------------------------------------
    boite_titre "Saisie des crédentiels de connexion sur la BD 11g source"

    while true; do
        read -r -p "Entrez le nom d'utilisateur DBA: " db_user
        if [[ -z "$db_user" ]]; then
            msg_status 1 "Le nom d'utilisateur ne peut pas être vide."
            continue
        fi
        break
    done

    while true; do
        read -s -r -p "Entrez le mot de passe pour $db_user: " db_user_pwd
        echo
        if [[ -z "$db_user_pwd" ]]; then
            msg_status 1 "Le mot de passe ne peut pas être vide."
            continue
        fi
        break
    done

    boite_titre "Saisie des crédentiels de connexion sur la BD 19c source"
    while true; do
        read -r -p "Entrez le nom d'utilisateur DBA 19c (C##USER): " db_user19c
        if [[ -z "$db_user19c" ]]; then
            msg_status 1 "Le nom d'utilisateur ne peut pas être vide."
            continue
        fi
        break
    done

    while true; do
        read -s -r -p "Entrez le mot de passe pour $db_user19c: " db_user19c_pwd
        echo
        if [[ -z "$db_user19c_pwd" ]]; then
            msg_status 1 "Le mot de passe ne peut pas être vide."
            continue
        fi
        break
    done

    # On détermine le nom de l'instance 11g pour déterminer le répertoire où se trouve les dumps
    db11g_name=$(${SQLPLUS} -L -S /nolog <<SQL | sed 's/^[[:space:]]*//; s/[[:space:]]*$//;/^$/d'
set heading off feedback off pages 0 verify off echo off trimout on trimspool on
connect ${db_user}/${db_user_pwd}@${alias_db_src}
select instance_name from sys.v_\$instance ;
SQL
)
    _rc=$?
    if [[ $_rc -ne 0 ]]; then
        msg_status 1 "Connexion SQL*Plus échouée (code=$_rc). Vérifie db_user/db_user_pwd/alias_db_src."
        return 1
    fi

    # On détermine le nom du serveur 11g 
    host11g_name=$(${SQLPLUS} -L -S /nolog <<SQL | sed 's/^[[:space:]]*//; s/[[:space:]]*$//;/^$/d'
set heading off feedback off pages 0 verify off echo off trimout on trimspool on
connect ${db_user}/${db_user_pwd}@${alias_db_src}
select host_name from sys.v_\$instance ;
SQL
)

    # ----------------------------------------------------------------
    # Nouveau : proposer la sauvegarde chiffrée si aucun fichier n'existe
    # ----------------------------------------------------------------
    if [[ ! -f "${cred_file}" ]]; then
        local save_ans
        save_ans=$(Question_YesNo "Voulez-vous sauvegarder ces crédentiels dans un fichier chiffré (${cred_file}) ? ")
        if [[ "${save_ans}" == "Y" ]]; then
            echoT "Choisissez le moteur de chiffrement :"
            echoT "  1) gpg (recommandé)"
            echoT "  2) openssl"
            local enc_choice
            while true; do
                read -r -p "Votre choix [1/2] (défaut 1): " enc_choice
                enc_choice="${enc_choice:-1}"
                [[ "${enc_choice}" =~ ^[12]$ ]] && break
            done

            # Mot de passe avec confirmation
            local pass1 pass2
            while true; do
                read -s -r -p "Mot de passe de chiffrement : " pass1; echo
                read -s -r -p "Confirmez le mot de passe     : " pass2; echo
                if [[ -z "$pass1" ]]; then
                    msg_status 1 "Mot de passe vide."
                    continue
                fi
                if [[ "$pass1" != "$pass2" ]]; then
                    msg_status 2 "Les mots de passe ne correspondent pas. Réessayez.${RESET}"
                    continue
                fi
                break
            done

            umask 077
            local plain_tmp
            plain_tmp="$(mktemp /tmp/${user_tty}.cred.plain.XXXXXX)" || { echoT "${RED}ERREUR${RESET} : mktemp a échoué"; return 1; }
            {
                echo "db_user='${db_user}'"
                echo "db_user_pwd='${db_user_pwd}'"
                echo "db_user19c='${db_user19c}'"
                echo "db_user19c_pwd='${db_user19c_pwd}'"
            } > "${plain_tmp}"

            local enc_ok=0
            if [[ "${enc_choice}" == "1" ]]; then
                if command -v gpg >/dev/null 2>&1; then
                    # --pinentry-mode loopback pour éviter l'agent
                    printf "%s" "${pass1}" | gpg --batch --yes --quiet --pinentry-mode loopback --passphrase-fd 0 -c --cipher-algo AES256 -o "${cred_file}" "${plain_tmp}" 2>/dev/null && enc_ok=1
                else
                    echoT "gpg introuvable, bascule vers openssl."
                fi
            fi
            if [[ "${enc_ok}" -eq 0 ]]; then
                if command -v openssl >/dev/null 2>&1; then
                    openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -in "${plain_tmp}" -out "${cred_file}" -pass pass:"${pass1}" 2>/dev/null && enc_ok=1
                else
                    msg_status 1 "openssl introuvable — impossible de chiffrer."
                fi
            fi

            # Nettoyage du clair
            shred -u "${plain_tmp}" 2>/dev/null || rm -f "${plain_tmp}"
            unset pass1 pass2

            if [[ "${enc_ok}" -eq 1 ]]; then
                chmod 600 "${cred_file}" 2>/dev/null || true
                msg_status 0 "Crédentiels sauvegardés dans ${cred_file}."
            else
                msg_status 2 "Échec de la création du fichier chiffré (${cred_file})."
            fi
        fi
    fi

    return 0
}

function check_instance() {

    boite_titre "Valide si l'instance CDB et le PDB de destination sont ouverts"
    
    # Définit le flashback_time pour les exports Datapump
    flashback_time=`date +%Y-%m-%d%H:%M:%S`
    
    # Est-ce que l'instance est lancée
    local _chk_inst=$(ps -ef | grep "ora_smon_${ORACLE_SID}" | grep -v grep)

    # Vérifie si la version est bien 19c
    local _is_19c=$(${SQLPLUS} -S / as SYSDBA <<EOF | grep VALEUR | sed 's/VALEUR//;s/ //g'
select 'VALEUR', count(*) 
from v\$version 
where banner like '%19.0%';
exit
EOF
)

    local _pdb_exists=$(${SQLPLUS} -S / as SYSDBA <<EOF | grep VALEUR | sed 's/VALEUR//;s/ //g'
select 'VALEUR', count(*) 
from v\$pdbs 
where name = '$ORACLE_PDB_SID';
exit
EOF
)


    # Trim des espaces et retours à la ligne
    _is_19c=$(echo "${_is_19c}" | tr -d '[:space:]')
    _pdb_exists=$(echo "${_pdb_exists}" | tr -d '[:space:]')

    echo "_chk_inst:${_chk_inst}"
    echo "_is_19c:${_is_19c}"
    echo "_pdb_exists:${_pdb_exists}"
    if [[ -n "${_chk_inst}" && "${_is_19c}" == "1" && "${_pdb_exists}" == "1" ]]; then
        msg_status 0 "CDB ${ORACLE_SID} disponible et PDB ${ORACLE_PDB_SID} existe et est en version 19c"
    elif [[ -n "${_chk_inst}" && "${_pdb_exists}" == "0" ]]; then 
        msg_status 1 "Le PDB ${ORACLE_PDB_SID} n'existe pas dans le CDB ${ORACLE_SID}! Impossible de continuer!"
        statut=97
        fin
    else
        if [[ -z "${_chk_inst}" ]]; then
            msg_status 1 "L'instance ${ORACLE_SID} n'est pas lancée"
        elif [[ "${_is_19c}" != "1" ]]; then
            msg_status 1 "L'instance ${ORACLE_SID} n'est pas en 19c, validez que vous êtes sur le bon serveur"
        else
            msg_status 1 "Erreur non identifiable!"            
        fi
        statut=97
        fin
    fi
}

# Sélection des schémas utilitaire à migrer en fonction de la présence de la table RREMPLOYE.
# Sortie: remplit la variable globale MIGRATION_SCHEMAS (ex: "SCOTT,HR")
# Retour: 0 (succès), 1 (erreur de connexion ou aucun schéma listé et choix T)
# Sélection des schémas utilitaire à migrer en fonction de la présence de la table RREMPLOYE.
# Sortie: remplit la variable globale MIGR_SCHEMAS_UTIL (ex: "SCOTT,HR")
# Retour: 0 (succès), 1 (erreur de connexion ou aucun schéma listé et choix T)
function select_schema_util() {
    local _out _rc
    local -a IDS USERNAMES
    MIGR_SCHEMAS_UTIL=""
    imp_ctrl_log_partiel=""   # 0 = initial, 1 = partiel (sera renseigné si CTRL_LOG est sélectionné)

    boite_titre "Sélection des schémas utilitaires à migrer"
    
    if [[ ${save_parameters_tables} -eq 1 ]]; then
        # Si on demande de sauvegarder les tables de paramètres alors on ne peut pas migrer le schéma DB_EXPORT car sinon, 
        # s'il existe, il sera effacé et la sauvegarde serait alors effacée
        local _db_export=",'DB_EXPORT'" 
    else
        local _db_export="" 
    fi
    
    # Récupère la liste schémas utilitaires "numéro - username"
    _out=$(${SQLPLUS} -L -S /nolog <<SQL | sed 's/^[[:space:]]*//; s/[[:space:]]*$//;/^$/d'
set heading off feedback off pages 0 verify off echo off trimout on trimspool on
connect ${db_user}/${db_user_pwd}@${alias_db_src}
SELECT rownum || ' - ' || username FROM (SELECT username
FROM dba_users 
WHERE username IN ('BIUQ','CTRL_LOG','TABLEAU'${_db_export}) OR username like 'BIUQ%${schema_name}%' OR username like 'TAB%${schema_name}%'
ORDER BY username);
SQL
)
    _rc=$?
    if [[ $_rc -ne 0 ]]; then
        msg_status 1 "Connexion SQL*Plus échouée (code=$_rc). Vérifie db_user/db_user_pwd/alias_db_src."
        return 1
    fi

    # Nettoie sortie et gère le cas sans schéma
    _out=$(echo "$_out" | sed '/^[[:space:]]*$/d')

    echoT "***"
    echoT "*** Schémas Utilitaire disponibles :"
    echoT "***"
    while IFS= read -r line; do
        echoT "$line"
    done <<< "$_out"
    
    # Construit les tableaux IDS[] et USERNAMES[] à partir des lignes "N - OWNER"
    local line num username i=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        num=${line%% -*}
        username=${line#*- }
        num=$(echo "$num" | tr -d '[:space:]')
        username=$(echo "$username" | tr -d '[:space:]')
        IDS[i]=$num
        USERNAMES[i]=$username
        ((i++))
    done <<< "$_out"

    # Boucle de saisie/validation
    echo "ATTENTION: Ne pas choisir plusieurs schémas de même type: ex: BIUQ et BIUQTELUQSANDBOX"
    echo "           Il faut le faire en 2 étapes!"
    local choice normalized
    while true; do
        echoT " "
        read -r -p "Entrez les schémas à migrer (0 = aucun, T = tous, ou numéros séparés par des virgules): " choice
        normalized=$(echo "$choice" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')

        # 0 = aucun
        if [[ "$normalized" == "0" ]]; then
            MIGR_SCHEMAS_UTIL=""
            imp_ctrl_log_partiel=""   # rien de sélectionné ? n/a
            echoT "Aucun schéma utilitaire ne sera migré."
            return 0
        fi

        # T = tous
        if [[ "$normalized" == "T" ]]; then
            if ((${#USERNAMES[@]} == 0)); then
                msg_status 1 "Aucun schéma listé — impossible de choisir 'T'. Choisissez 0."
                continue
            fi
            MIGR_SCHEMAS_UTIL=$(IFS=,; echo "${USERNAMES[*]}")

            # Si CTRL_LOG fait partie de la sélection, demander initial/partiel
            if [[ ",${MIGR_SCHEMAS_UTIL}," == *",CTRL_LOG,"* ]]; then
                echoT " "
                echoT "*** ${YELLOW}CTRL_LOG sélectionné${RESET} :"
                echoT "0 = Chargement initial complet de CTRL_LOG"
                echoT "1 = Vues & triggers uniquement, liés à ${schema_name}"
                local rep
                while true; do
                    read -r -p "Votre choix pour CTRL_LOG (0=initial, 1=partiel): " rep
                    if [[ "$rep" == "0" || "$rep" == "1" ]]; then
                        imp_ctrl_log_partiel="$rep"
                        break
                    fi
                    echoT "${YELLOW}Entrée invalide${RESET} : répondez 0 ou 1."
                done
            else
                imp_ctrl_log_partiel=""   # non concerné
            fi

            echoT "Tous les schémas seront migrés: $MIGR_SCHEMAS_UTIL"
            echoT " "
            #echoT "***"
            #echoT "*** ${YELLOW}ATTENTION${RESET}: S'il(s) existe(nt), ce(s) schéma(s) utilitaire(s) sera(ont) effacé(s) du PDB ${ORACLE_PDB_SID} avant l'import!"
            #echoT "***"
            #continue_execution "Souhaitez-vous poursuivre la migration?"
            #echoT " "
            echoT "*****"
            echoT " "
            return 0
        fi

        # Liste de numéros séparés par des virgules
        if [[ "$normalized" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
            if ((${#USERNAMES[@]} == 0)); then
                msg_status 1 "Aucun schéma n’est disponible. Entrez 0."
                continue
            fi

            # Valide chaque numéro
            IFS=',' read -r -a nums <<< "$normalized"
            local -A wanted=()
            local ok=1
            local n id
            for n in "${nums[@]}"; do
                # Vérifie si n est dans IDS[]
                local match=0
                for id in "${IDS[@]}"; do
                    if [[ "$n" == "$id" ]]; then
                        match=1
                        break
                    fi
                done
                if (( match == 0 )); then
                    msg_status 1 "Le numéro '$n' n'est pas dans la liste. Réessaie."
                    ok=0
                    break
                fi
                wanted["$n"]=1  # dédoublonne
            done
            if (( ok == 0 )); then
                continue
            fi

            # Construit MIGR_SCHEMAS_UTIL dans l’ordre des IDS
            local selected=()
            for ((i=0; i<${#IDS[@]}; i++)); do
                if [[ -n "${wanted[${IDS[$i]}]}" ]]; then
                    selected+=("${USERNAMES[$i]}")
                fi
            done
            MIGR_SCHEMAS_UTIL=$(IFS=,; echo "${selected[*]}")

            # Si CTRL_LOG fait partie de la sélection, demander initial/partiel
            if [[ ",${MIGR_SCHEMAS_UTIL}," == *",CTRL_LOG,"* ]]; then
                echoT " "
                echoT "*** ${YELLOW}CTRL_LOG sélectionné${RESET} :"
                echoT "0 = Chargement initial complet de CTRL_LOG (DROP de CTRL_LOG)"
                echoT "1 = Vues & triggers uniquement, liés à ${schema_name}"
                local rep
                while true; do
                    read -r -p "Votre choix pour CTRL_LOG (0=initial, 1=partiel): " rep
                    if [[ "$rep" == "0" || "$rep" == "1" ]]; then
                        imp_ctrl_log_partiel="$rep"
                        break
                    fi
                    echoT "${YELLOW}Entrée invalide${RESET} : répondez 0 ou 1."
                done
            else
                imp_ctrl_log_partiel=""   # non concerné
            fi
            
            if [[ "${schema_name}" != "${dest_schema_name}" && ",${MIGR_SCHEMAS_UTIL}," == *",BIUQ,"* ]]; then
                echoT " "
                echoT "*** ${YELLOW}BIUQ sélectionné et schema_name != dest_schema_name${RESET}"
                local _in
                read -r -p "Nouveau nom du schéma BIUQ [BIUQ]: " _in
                biuq_new_name="${_in:-BIUQ}"

                _in=""
                read -r -p "Nom du schéma applicatif Safirh que BIUQ doit cibler [${dest_schema_name}]: " _in
                biuq_target_schema="${_in:-${dest_schema_name}}"
                if [[ "${biuq_new_name}" == "BIUQ" ]]; then
                    echoT "BIUQ ne sera pas renommé"
                else
                    echoT "BIUQ sera renommé en: ${biuq_new_name}"
                fi
                echoT "${biuq_new_name} pointera vers le schéma Safirh: ${biuq_target_schema}"
                echoT " "
            fi

            if [[ "${schema_name}" != "${dest_schema_name}" && ",${MIGR_SCHEMAS_UTIL}," == *",TABLEAU,"* ]]; then
                echoT " "
                echoT "*** ${YELLOW}TABLEAU sélectionné et schema_name != dest_schema_name${RESET}"
                local _in
                read -r -p "Nouveau nom du schéma TABLEAU [TABLEAU]: " _in
                tableau_new_name="${_in:-BIUQ}"

                _in=""
                read -r -p "Nom du schéma applicatif Safirh que TABLEAU référence [${dest_schema_name}]: " _in
               tableau_target_schema="${_in:-${dest_schema_name}}"

                if [[ "${tableau_new_name}" == "BIUQ" ]]; then
                    echoT "TABLEAU ne sera pas renommé"
                else
                    echoT "TABLEAU sera renommé en: ${tableau_new_name}"
                fi
                echoT "TABLEAU pointera vers le schéma Safirh: ${tableau_target_schema}"
                echoT " "
            fi

            echoT "Schéma(s) utilitaire(s) sélectionné(s): $MIGR_SCHEMAS_UTIL"
            echoT " "
            echoT "*****"
            echoT " "
            return 0
        fi

        echoT "Entrée invalide. Utilise 0, T, ou une liste de numéros (ex: 1,3,5)."
    done
}

# Fonction : select_schema_app
#
# Description : 
#   • Récupère la liste des schémas contenant la table RREMPLOYE.
#   • Demande à l’utilisateur de choisir un schéma (ou 0 pour aucun).
#   • Ensuite, demande le nom du schéma de destination.
#     Si le schéma source est vide (aucun schéma Safirh choisi), on
#     vérifie que le schéma de destination existe dans la base locale
#     (connexion ${SQLPLUS} / as sysdba).  La requête suivante doit renvoyer
#     1 :   SELECT COUNT(*) FROM dba_tables WHERE owner = $dest_schema_name
#           AND table_name = 'RREMPLOYE';
#     Si le résultat est 0, on affiche un message d’erreur et l’on termine
#     le script.
#
# Tous les messages affichés sont en français.
# ---------------------------------------------------------------
function select_schema_app() {
    local _out _rc
    local -a IDS OWNERS
    schema_name=""          # Schéma source choisi par l’utilisateur
    save_parameters_tables=0

    boite_titre "Sélection du schéma Safirh à migrer"

    # -----------------------------------------------------------------
    # 1) Récupération de la liste des schémas contenant RREMPLOYE
    # -----------------------------------------------------------------
    _out=$(${SQLPLUS} -L -S /nolog <<SQL | sed 's/^[[:space:]]*//; s/[[:space:]]*$//;/^$/d'
set heading off feedback off pages 0 verify off echo off trimout on trimspool on
connect ${db_user}/${db_user_pwd}@${alias_db_src}
select rownum || ' - ' || owner
  from (select distinct owner 
          from dba_tables 
         where table_name = 'RREMPLOYE' 
         order by owner);
SQL
)
    _rc=$?
    if [[ $_rc -ne 0 ]]; then
        echoT "**************"
        echoT "*** ${RED}ERREUR${RESET} *** Connexion SQL*Plus échouée (code=$_rc). Vérifie db_user/db_user_pwd/alias_db_src."
        echoT "**************"
        return 1
    fi

    # Nettoyage de la sortie
    _out=$(echo "${_out}" | sed '/^[[:space:]]*$/d')

    # Contrôle mode_script=2 si aucun schéma trouvé
    if [[ "${mode_script}" == "2" && -z "$_out" ]]; then
        echoT "Vous avez choisi le mode \"Copie+Migration\" mais la BD 11G source ne contient pas de schéma safirh de Production. Impossible de continuer!"
        exit 1
    fi


    if [[ -z "$_out" ]]; then
        echoT "Aucun schéma Safirh n'a été trouvé. Choisissez 0 pour ne rien sélectionner."
    else
        echoT "***"
        echoT "*** Schémas Safirh disponibles dans la BD ${BLUE}${db11g_name}${RESET} sur ${BLUE}${host11g_name}${RESET} :"
        echoT "***"
        while IFS= read -r _l; do
            [[ -n "$_l" ]] && echoT "$_l"
        done <<< "$_out"
    fi

    # -----------------------------------------------------------------
    # 2) Construction des tableaux IDS[] et OWNERS[]
    # -----------------------------------------------------------------
    local line num owner i=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        num=${line%% -*}
        owner=${line#*- }
        num=$(echo "$num"   | tr -d '[:space:]')
        owner=$(echo "$owner" | tr -d '[:space:]')
        IDS[i]=$num
        OWNERS[i]=$owner
        ((i++))
    done <<< "$_out"

    local total=${#OWNERS[@]}

    # -----------------------------------------------------------------
    # 3) Boucle de saisie/validation pour le schéma source
    # -----------------------------------------------------------------
    local choice normalized
    while true; do
        echoT ""
        read -r -p "Sélectionne un schéma (0 = aucun, ou un seul numéro): " choice
        normalized=${choice//[[:space:]]/}

        # 0 = aucun schéma source
        if [[ "$normalized" == "0" ]]; then
            # En mode 2, interdit
            if [[ "${mode_script}" == "2" ]]; then
                echoT "Vous avez choisi le mode \"Copie+Migration\" mais la BD 11G source ne contient pas de schéma safirh de Production. Impossible de continuer!"
                exit 1
            fi

            schema_name=""
            echoT "Aucun schéma applicatif ne sera migré."
            break
        fi

        # Autoriser uniquement un entier (rejette T, listes, plages, etc.)
        if [[ "$normalized" =~ ^[0-9]+$ ]]; then
            if (( total == 0 )); then
                echoT "${RED}ERREUR${RESET} Aucun schéma n’est disponible. Entrez 0."
                continue
            fi

            # Vérifie que le numéro existe et récupère le nom
            local match=0
            for ((i=0; i<total; i++)); do
                if [[ "${IDS[$i]}" == "$normalized" ]]; then
                    schema_name="${OWNERS[$i]}"
                    match=1
                    break
                fi
            done
            if (( match == 0 )); then
                echoT "${RED}ERREUR${RESET}: Le numéro '$normalized' n'est pas dans la liste. Réessaie."
                continue
            fi

            # en mode 2, le schéma choisi doit se terminer par PROD
            if [[ "${mode_script}" == "2" && ! "${schema_name}" =~ PROD$ ]]; then
                echoT "Vous avez choisi le mode \"Copie+Migration\" mais la BD 11G source ne contient pas de schéma safirh de Production. Impossible de continuer!"
                exit 1
            fi

            echoT "Schéma Safirh sélectionné : $schema_name"

            echoT " "
            echoT "*****"
            echoT " "
            break
        fi

        # Tout le reste est invalide (T, virgules, tirets, texte, etc.)
        echoT "${RED}ERREUR${RESET} Tu dois sélectionner un SEUL numéro ou 0."
    done

    # -----------------------------------------------------------------
    # 4) Demande du schéma de destination (dest_schema_name)
    # -----------------------------------------------------------------
    boite_titre "Sélection du schéma destination"
    dest_schema_name=""
    read -r -p "Entrez le nom du schéma de destination [${schema_name}]: " dest_schema_name
    if [[ -z "$dest_schema_name" ]]; then
        dest_schema_name="$schema_name"
    fi
    
    if [[ -n "${schema_name}" && "$dest_schema_name" != "$schema_name" ]]; then
        schema_name_remap="${schema_name}:${dest_schema_name}"
    fi
     
    echoT " "
    echoT "Schéma de destination choisi : ${BOLD}$dest_schema_name${RESET}"
    echoT " "
    # -----------------------------------------------------------------
    # 5) Vérification du schéma de destination si aucun schéma source n'a été sélectionné
    # -----------------------------------------------------------------
    boite_titre "Vérification du schéma de destination si aucun schéma source n'a été sélectionné"
    local cnt
    cnt=$(${SQLPLUS} -L -S / as sysdba <<EOF
set heading off feedback off pages 0 verify off echo off trimout on trimspool on
select count(*) from dba_tables where owner = UPPER('$dest_schema_name') and table_name = 'RREMPLOYE';
exit;
EOF
)

    if [[ -z "$schema_name" && "$cnt" -eq 0 ]]; then
        echoT "**************"
        echoT "*** ${RED}ERREUR${RESET} *** Si vous ne migrez pas de schéma Safirh, le schéma de destination doit exister!"
        echoT "**************"
        echoT " "
        echoT "Impossible de continuer!"
        echoT " "
        fin   # termine tout le script
    elif [[ -n "$schema_name" && "$cnt" -eq 1 ]]; then
        echoT "${YELLOW}ATTENTION${RESET} : Le schéma de destination ${dest_schema_name} existe donc, il sera effacé avant l'import!"
        continue_execution "Souhaitez-vous poursuivre la migration?"
        echoT " "
        echoT "Sauvegarde des tables de paramètres:"
        echoT "À la prochaine question, vous devez répondre NON s'il s'agit de la première migration du schéma $dest_schema_name."
        echoT "Si vous répondez OUI, il faut que le schéma DB_EXPORT soit déjà migré."
        local _result=$(Question_YesNo "Souhaitez-vous effectuer la sauvegarde des tables de paramètres du schéma $dest_schema_name ?")
        if [ "${_result}" = "Y" ] ; then
            echoT " "
            echoT "*** Ajout de l'étape de sauvegarde des tables de paramètres du schéma $$dest_schema_name"
            echoT " "
            save_parameters_tables=1
        else
            echoT " "
            echoT "*** Vous avez choisi de ne pas sauvegarder!"
            echoT " "
            save_parameters_tables=0
        fi        

    fi
    
    # En mode copie+migration, on ne détruit pas les schémas connexes, donc, on ne les recharge pas
    if [[ -n "$schema_name" && ${mode_script} -ne 2 ]]; then
        
        boite_titre "Détermination des schémas connexes et du remappage"

        # -----------------------------------------------------------------
        # 3a) Récupération des schémas contenant le nom dans schema_name
        #     -> liste séparée par des virgules dans schema_name_childs
        # -----------------------------------------------------------------
        schema_name_childs=$(${SQLPLUS} -L -S /nolog <<SQL | sed 's/^[[:space:]]*//; s/[[:space:]]*$//;/^$/d'
set heading off feedback off pages 0 verify off echo off trimout on trimspool on
connect ${db_user}/${db_user_pwd}@${alias_db_src}
select listagg(username, ',') within group (order by username)
  from dba_users
 where username like '%'||upper('${schema_name}')||'%' and username!='${schema_name}';
SQL
)
        # Nettoyage espaces/retours
        schema_name_childs=$(echo "$schema_name_childs" | sed 's/^\s\+//; s/\s\+$//')

        if [[ -n "$schema_name_childs" ]]; then
            echoT "Schémas liés au schéma '${schema_name}' : ${schema_name_childs}"
            echoT "Ils seront traités en même temps que le schéma '${schema_name}'"
        else
            echoT "Aucun schéma lié à '${schema_name}' n'a été trouvé."
        fi
        if [[ "$schema_name" = "${dest_schema_name}" ]]; then
            echoT "Le schéma Safirh de destination étant identique au schéma source, il n'y aura pas de remappage des schémas connexes"
        else
            # Variable qui contient l'instruction de remappage des schémas pur impdp
            schema_name_childs_remap=$(${SQLPLUS} -L -S /nolog <<SQL | sed 's/^[[:space:]]*//; s/[[:space:]]*$//;/^$/d'
set heading off feedback off pages 0 verify off echo off trimout on trimspool on
connect ${db_user}/${db_user_pwd}@${alias_db_src}
select listagg(username||':'||REPLACE(username,'${schema_name}','${dest_schema_name}'), ',') within group (order by username)
  from dba_users
 where username like '%'||upper('${schema_name}')||'%' and username!='${schema_name}';
SQL
)
            # Variable qui contient la liste des utilisateurs remappés
            dest_schema_name_childs=$(${SQLPLUS} -L -S /nolog <<SQL | sed 's/^[[:space:]]*//; s/[[:space:]]*$//;/^$/d'
set heading off feedback off pages 0 verify off echo off trimout on trimspool on
connect ${db_user}/${db_user_pwd}@${alias_db_src}
select listagg(REPLACE(username,'${schema_name}','${dest_schema_name}'), ',') within group (order by username)
  from dba_users
 where username like '%'||upper('${schema_name}')||'%' and username!='${schema_name}';
SQL
)
            echoT "Le schéma Safirh de destination étant différent du schéma source, il y aura remappage des schémas à l'import:"
            echoT "REMAP_SCHEMA=${schema_name_childs_remap}"
        fi    
        
            
    fi

    return 0
}

# Liste les schémas utilisateurs (dba_users filtrés) et permet une sélection par
#  - 0 : aucun
#  - T : tous
#  - listes et/ou plages : ex. "2-5,7,10-12"
# Sortie : remplit MIGRATION_SCHEMAS (ex: "USER1,USER2")
function select_schema_user() {
    local _out _rc
    local -a IDS USERS
    MIGRATION_SCHEMAS=""

    boite_titre "Sélection des schémas utilisateurs à migrer"

    # Récupération des usernames (numérotés) via SQL*Plus
    _out=$(${SQLPLUS} -L -S /nolog <<SQL | sed 's/^[[:space:]]*//; s/[[:space:]]*$//;/^$/d'
set heading off feedback off pages 0 verify off echo off trimout on trimspool on define off
connect ${db_user}/${db_user_pwd}@${alias_db_src}
WITH u AS (
  SELECT username
  FROM   dba_users
  WHERE  username NOT IN ('BIUQ','CTRL_LOG','TABLEAU','DB_EXPORT')
     AND username NOT IN ('DBSNMP','DIP','CTXSYS','ANONYMOUS','APEX_040200','APEX_PUBLIC_USER','APPQOSSYS','EXFSYS',
                          'EXT_SYSPER','FLOWS_FILES','MDDATA','MDSYS','MGMT_VIEW','OLAPSYS','ORACLE_OCM','ORDDATA',
                          'ORDPLUGINS','ORDSYS','OUTLN','OWBSYS','OWBSYS_AUDIT','PERFSTAT','SCOTT',
                          'SI_INFORMTN_SCHEMA','SYS','SYSMAN','SYSTEM','WMSYS','XDB','XS\$NULL','EARSENAU','EUGENE','MMINIER',
                          'CLOUBIER','EARSENAU','EUGENE','GROULEAU','HLANDRY','MCARON','MORTIZ','RMGUTIER','RROULEAU','SBRAVO','SROY')
     AND username NOT LIKE '%${schema_name}%'
     AND username NOT LIKE 'BIUQ%${schema_name}%' 
     AND username NOT LIKE 'TAB%${schema_name}%'
     AND account_status='OPEN' 
)
SELECT rownum || ' - ' || username
FROM   (SELECT username FROM u ORDER BY username);
SQL
)
    _rc=$?
    if [[ $_rc -ne 0 ]]; then
        echoT "**************"
        echoT "*** ${RED}ERREUR${RESET} *** Connexion SQL*Plus échouée (code=$_rc). Vérifie db_user/db_user_pwd/alias_db_src."
        echoT "**************"
        return 1
    fi

    # Nettoyage lignes vides
    _out=$(echo "$_out" | sed '/^[[:space:]]*$/d')

    if [[ -z "$_out" ]]; then
        echoT "Aucun schéma utilisateur éligible trouvé."
        # Seule l’option '0' a du sens
    else
        echoT "***"
        echoT "*** Schémas utilisateurs disponibles :"
        echoT "***"
        echoT "$_out"    
    fi

    # Remplit IDS[] et USERS[] à partir de "N - USERNAME"
    local line num user i=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        num=${line%% -*}
        user=${line#*- }
        num=$(echo "$num"  | tr -d '[:space:]')
        user=$(echo "$user" | tr -d '[:space:]')
        IDS[i]=$num
        USERS[i]=$user
        ((i++))
    done <<< "$_out"

    local total=${#USERS[@]}

    # Boucle de sélection
    local choice normalized
    while true; do
        echo
        read -r -p "Sélection (0 = aucun, T = tous, plages/listes ex: 2-5,7,10-12): " choice
        normalized=$(echo "$choice" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')

        # 0 ou T doivent être seuls
        if [[ "$normalized" == "0" ]]; then
            MIGRATION_SCHEMAS=""
            echoT "Aucun schéma ne sera migré."
            return 0
        fi
        if [[ "$normalized" == "T" ]]; then
            if (( total == 0 )); then
                echoT "ERREUR: Aucun schéma listé — 'T' impossible. Choisissez 0."
                continue
            fi
            MIGRATION_SCHEMAS=$(IFS=,; echo "${USERS[*]}")
            echoT "Tous les schémas seront migrés: $MIGRATION_SCHEMAS"
            return 0
        fi
        # Interdit de mélanger 0/T avec d'autres tokens
        if [[ "$normalized" == *T* ]]; then
            echoT "ERREUR: 'T' doit être seul."
            continue
        fi
        if [[ "$normalized" =~ (^|,)0(,|$) ]]; then
            echoT "ERREUR: '0' doit être seul."
            continue
        fi

        # Valide pattern: nombres et/ou plages, séparés par des virgules
        if ! [[ "$normalized" =~ ^([0-9]+(-[0-9]+)?)(,([0-9]+(-[0-9]+)?))*$ ]]; then
            echoT "Entrée invalide. Utilise 0, T, ou une liste/plage (ex: 1,3-5,7)."
            continue
        fi

        if (( total == 0 )); then
            echoT "ERREUR: Aucun schéma n’est disponible. Entrez 0."
            continue
        fi

        # Parse et valide chaque token/range
        IFS=',' read -r -a tokens <<< "$normalized"
        declare -A wanted=()
        ok=1

        for tok in "${tokens[@]}"; do
            if [[ "$tok" == *-* ]]; then
                # Plage a-b
                IFS='-' read -r a b <<< "$tok"
                # Vérifs numériques et bornes
                if ! [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ ]]; then
                    echoT "ERREUR: Plage non numérique: $tok"
                    ok=0; break
                fi
                if (( a < 1 || b < 1 || a > total || b > total )); then
                    echoT "ERREUR: Plage hors limites (1..$total): $tok"
                    ok=0; break
                fi
                if (( a > b )); then
                    echoT "ERREUR: Plage décroissante non supportée: $tok (utilise $b-$a si besoin d'inverser)."
                    ok=0; break
                fi
                for ((n=a; n<=b; n++)); do wanted["$n"]=1; done
            else
                # Numéro simple
                if ! [[ "$tok" =~ ^[0-9]+$ ]]; then
                    echoT "ERREUR: Numéro invalide: $tok"
                    ok=0; break
                fi
                if (( tok < 1 || tok > total )); then
                    echoT "ERREUR: Numéro hors limites (1..$total): $tok"
                    ok=0; break
                fi
                wanted["$tok"]=1
            fi
        done

        (( ok == 0 )) && continue

        # Construit la liste finale dans l’ordre d’affichage
        local selected=()
        for ((i=0; i<total; i++)); do
            # IDS[i] vaut i+1, mais on reste générique
            if [[ -n "${wanted[${IDS[$i]}]}" ]]; then
                selected+=("${USERS[$i]}")
            fi
        done

        MIGRATION_SCHEMAS=$(IFS=,; echo "${selected[*]}")
        echoT "Schémas utilisateurs sélectionnés: $MIGRATION_SCHEMAS"
        echoT " "
#        echoT "***"
#        echoT "*** ATTENTION: S'il(s) existe(nt), ces schémas utilisateurs seront effacés du PDB ${ORACLE_PDB_SID} avant l'import!"
#        echoT "***"
#        continue_execution "Souhaitez-vous poursuivre la migration?"
        echoT " "
        echoT "*****"
        echoT " "
        return 0
    done
}

# Prompt chatGPT pour validation_tablespaces:
# Crée moi un fonction bash avec le nom: validation_tablespaces. Dans cette fonction, on va valider l'existence des tablespaces requis dans la destination 19c par rapport à la source 11g. La connexion ${SQLPLUS} sur la base 19c se fait de cette façon puisque le script sur le serveur 19c: ${SQLPLUS} -L -S / as sysdba Sur la base 11g comme ceci: ${SQLPLUS} -L -S "${db_user}/${db_user_pwd}@${alias_db_src}" Validation 1: On cherche si le tablespace applicatif existe: Sur la BD 11g: On exécute la requête suivante pour trouver le tablespace du schéma $schema_name: select distinct tablespace_name from dba_segments where owner='$schema_name'; Il faut prévoir le cas où cette requête retourne plusieurs tablespaces en interrompant le script et en disant qu'il ne gère pas les schémas avec plusieurs tablespaces: afficher les tablespaces en question. Ensuite, on vérifie sur la BD 19c que ce tablespace existe. Si ce n'est pas le cas, on liste les tablespaces sur 19c sauf SYSTEM et SYSAUX, puis on demande à l'utilisateur de choisir le tablespace de destination. On enregistre le nom de ce tablespace dans la variable globale remap_tbs_dest_schema_name. Validation 2: Validation que le tablespace des autres schémas migrés (variables $MIGRATION_SCHEMAS et $MIGR_SCHEMAS_UTIL (attention, elles peuvent être vides) ) existe bien dans la BD 19c. À la différence de la validation précédent, le script ne gère pas le remappage de tablespace pour ces usagers. Si un tablespace n'est pas trouvé, le script s'arrête après avoir listé le ou les tablespaces manquants.
function validation_tablespaces() {
    # Valide les tablespaces requis 11g -> 19c
    # Variables attendues en global :
    #   db_user, db_user_pwd, alias_db_src, schema_name
    #   MIGRATION_SCHEMAS, MIGR_SCHEMAS_UTIL (peuvent être vides)
    #   remap_tbs_dest_schema_name (résultat pour le schéma principal)

    local _src_tbs_lines
    local _src_tbs=""
    local -a _lines
    local -a _tbs19
    local choice
    
    boite_titre "Validation des tablespaces dans la destination"

    # --- utilitaires locaux ---
    _trim() { sed 's/^[[:space:]]*//; s/[[:space:]]*$//' ; }
    _uniq_push() {
        # $1=valeur ; $2=nom tableau (référence indirecte)
        local v="$1"
        local -n ref="$2"
        local x
        for x in "${ref[@]}"; do [[ "$x" == "$v" ]] && return 0; done
        ref+=("$v")
    }

    # ========== Validation 1 : schéma principal ==========
    echoT "***"
    echoT "*** Validation du tablespace pour le schéma principal: ${schema_name}"
    echoT "***"

    _src_tbs_lines=$(${SQLPLUS} -L -S /nolog <<SQL | sed 's/^[[:space:]]*//; s/[[:space:]]*$//;/^$/d'
set pages 0 lines 32767 feedback off verify off heading off echo off termout off timing off
connect ${db_user}/${db_user_pwd}@${alias_db_src}
select distinct tablespace_name
from dba_segments
where owner = upper('${schema_name}')
order by 1;
exit
SQL
)
    # Nettoyage / split (pas de \s avec grep POSIX)
    mapfile -t _lines < <(printf "%s\n" "${_src_tbs_lines}" | sed -e 's/\r$//' | awk 'NF' | _trim)

    if [[ ${#_lines[@]} -eq 0 ]]; then
        echoT "ERREUR: Aucun segment trouvé pour le schéma ${schema_name} sur la BD 11g (tablespace inconnu). Non géré."
        return 1
    elif [[ ${#_lines[@]} -gt 1 ]]; then
        echoT "ERREUR: Le schéma ${schema_name} possède plusieurs tablespaces sur la 11g. Non géré."
        for t in "${_lines[@]}"; do echoT " - ${t}"; done
        return 1
    else
        _src_tbs="${_lines[0]}"
        echoT "Tablespace source détecté (11g): ${_src_tbs}"
    fi

    # Vérifie existence sur 19c
    local _exists19
    _exists19=$(${SQLPLUS} -L -S / as sysdba <<SQL
set pages 0 lines 32767 feedback off verify off heading off echo off termout off timing off
select count(*) from dba_tablespaces where tablespace_name = upper('${_src_tbs}');
exit
SQL
)
    _exists19=$(_trim <<<"${_exists19}")

    if [[ "${_exists19}" == "0" ]]; then
        echoT "ATTENTION: Le tablespace ${_src_tbs} n'existe pas sur la 19c."
        echoT "Veuillez choisir un tablespace de destination sur la 19c (hors SYSTEM/SYSAUX)."

        # Liste des tbs 19c proposés
        local _list19
        _list19=$(${SQLPLUS} -L -S / as sysdba <<SQL
set pages 0 lines 32767 feedback off verify off heading off echo off termout off timing off
select tablespace_name
from dba_tablespaces
where tablespace_name not in ('SYSTEM','SYSAUX')
order by 1;
exit
SQL
)
        mapfile -t _tbs19 < <(printf "%s\n" "${_list19}" | sed -e 's/\r$//' | awk 'NF' | _trim)

        if [[ ${#_tbs19[@]} -eq 0 ]]; then
            echoT "ERREUR: Aucun tablespace disponible (hors SYSTEM/SYSAUX) trouvé sur la 19c."
            return 1
        fi

        echoT "Sélectionnez un tablespace de destination pour faire le REMAP_TABLESPACE:"
        for i in "${!_tbs19[@]}"; do
            printf "%-3s %s\n" "$((i+1)))" "${_tbs19[$i]}" | while read -r l; do echoT "$l"; done
        done

        while true; do
            read -p "Entrez votre choix (1-${#_tbs19[@]}): " choice
            if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 && $choice -le ${#_tbs19[@]} ]]; then
                tbs_dest_schema_name="${_tbs19[$((choice-1))]}"
                remap_tbs_dest_schema_name="${_src_tbs}:${_tbs19[$((choice-1))]}"
                echoT "Remappage du tablespace de destination: ${remap_tbs_dest_schema_name}"
                break
            else
                echoT "Choix invalide. Entrez un nombre entre 1 et ${#_tbs19[@]}."
            fi
        done
    else
        # Pas de remap nécessaire pour le schéma principal
        remap_tbs_dest_schema_name=""
        tbs_dest_schema_name=${_src_tbs}
        echoT "OK: Le tablespace ${_src_tbs} existe sur 19c. Pas de remapping requis."
    fi

    # ========== Validation 2 : autres schémas migrés ==========
    echoT "***"
    echoT "*** Validation des tablespaces pour les autres schémas à migrer…"
    echoT "***"

    # Construit la liste de schémas (peuvent être vides) — CSV attendus
    local -a _other_schemas=()
    IFS=',' read -r -a _mig_arr  <<< "${MIGRATION_SCHEMAS:-}"
    IFS=',' read -r -a _util_arr <<< "${MIGR_SCHEMAS_UTIL:-}"

    local s
    for s in "${_mig_arr[@]}"; do
        s="${s//[[:space:]]/}"
        [[ -n "$s" ]] && _uniq_push "${s^^}" _other_schemas
    done
    for s in "${_util_arr[@]}"; do
        s="${s//[[:space:]]/}"
        [[ -n "$s" ]] && _uniq_push "${s^^}" _other_schemas
    done

    # Retire le schéma principal s'il est présent
    local _main_up="${schema_name^^}"
    local -a _tmp=()
    for s in "${_other_schemas[@]}"; do [[ "$s" != "$_main_up" ]] && _tmp+=("$s"); done
    _other_schemas=("${_tmp[@]}")

    if [[ ${#_other_schemas[@]} -eq 0 ]]; then
        echoT "Aucun autre schéma à valider. Étape terminée."
        return 0
    fi

    local -a _missing_tbs=()

    for sch in "${_other_schemas[@]}"; do
        echoT "Schéma: ${sch}"

        local _tbs_list
        _tbs_list=$(${SQLPLUS} -L -S /nolog <<SQL
set pages 0 lines 32767 feedback off verify off heading off echo off termout off timing off
connect ${db_user}/${db_user_pwd}@${alias_db_src}
select distinct tablespace_name
from dba_segments
where owner = upper('${sch}')
union
select distinct default_tablespace from dba_users where username = upper('${sch}')
order by 1;
exit
SQL
)
        mapfile -t _lines < <(printf "%s\n" "${_tbs_list}" | sed -e 's/\r$//' | awk 'NF' | _trim)

        if [[ ${#_lines[@]} -eq 0 ]]; then
            echoT "  - Aucun tablespace trouvé (segments et DEFAULT absents) ? BLOQUANT"
            _uniq_push "UNKNOWN_TBS_FOR_${sch}" _missing_tbs
            continue
        fi

        local t _ex
        for t in "${_lines[@]}"; do
            _ex=$(${SQLPLUS} -L -S / as sysdba <<SQL
set pages 0 lines 32767 feedback off verify off heading off echo off termout off timing off
select count(*) from dba_tablespaces where tablespace_name = upper('${t}');
exit
SQL
)
            _ex=$(_trim <<<"${_ex}")
            if [[ "${_ex}" == "0" ]]; then
                echoT "  - ${t} : ABSENT sur 19c"
                _uniq_push "${t}" _missing_tbs
            else
                echoT "  - ${t} : OK"
            fi
        done
    done

    if [[ ${#_missing_tbs[@]} -gt 0 ]]; then
        echoT " "
        echoT "ERREUR: Tablespaces requis absents sur la 19c (autres schémas) :"
        local m
        for m in "${_missing_tbs[@]}"; do echoT " - ${m}"; done
        echoT "Aucun remapping automatique n'est géré pour ces schémas. Corrigez la situation puis relancez."
        fin
    fi
    echoT "***"
    echoT "*** Validation terminée: tous les tablespaces requis existent sur la 19c."
    echoT "***"
    echoT " "
    return 0
}

function dmp_setup(){
    
    local _v_date=$(date +%Y%m%d)

    # Concatène MIGRATION_SCHEMAS et MIGR_SCHEMAS_UTIL -> schema_users (en gérant les cas vides)
    schema_users=""
    if [[ -n "${MIGRATION_SCHEMAS:-}" && -n "${MIGR_SCHEMAS_UTIL:-}" ]]; then
        schema_users="${MIGRATION_SCHEMAS},${MIGR_SCHEMAS_UTIL}"
    elif [[ -n "${MIGRATION_SCHEMAS:-}" ]]; then
        schema_users="${MIGRATION_SCHEMAS}"
    elif [[ -n "${MIGR_SCHEMAS_UTIL:-}" ]]; then
        schema_users="${MIGR_SCHEMAS_UTIL}"
    fi

    # (Optionnel) nettoyage espaces accidentels autour des virgules
    schema_users=$(echo "$schema_users" | sed -e 's/[[:space:]]\+//g' -e 's/,\{2,\}/,/g' -e 's/^,//' -e 's/,$//')

    # Variables globales pour se souvenir des choix d'export
    export_meta_safirh=0
    export_data_safirh=0
    export_users=0

    if [[ -n $schema_name ]]; then
        boite_titre "Choix de l'export des métadonnées du schéma Safirh 11g ${schema_name}"
        echoT "Deux possibilités:"
        echoT "  1 - L'export est fait par le script"
        echoT "  2 - Vous choisissez un dump existant dans le répertoire : ${imp_dp_dir}"
        echoT " "
        local _result
        _result=$(Question_Number "Quelle option choisissez-vous?" "1,2")
        if [[ "${_result}" = "1" ]]; then
            f_dmp_meta_safirh="${db11g_name}_${schema_name}_meta_${_v_date}.dmp"
            export_meta_safirh=1
            echoT "L'export se fera dans ${imp_dp_dir} sous le nom ${f_dmp_meta_safirh}"
        else
            choix_dmp "${imp_dp_dir}" "f_dmp_meta_safirh"
            export_meta_safirh=0
        fi
        f_log_meta_safirh="expdp_${f_dmp_meta_safirh%.dmp}.log"
        
        boite_titre "Choix de l'export des données du schéma Safirh 11g ${schema_name}"
        echoT "Deux possibilités:"
        echoT "  1 - L'export est fait par le script"
        echoT "  2 - Vous choisissez un dump existant dans le répertoire : ${imp_dp_dir}"
        echoT " "
        _result=$(Question_Number "Quelle option choisissez-vous?" "1,2")
        if [[ "${_result}" = "1" ]]; then
            f_dmp_data_safirh="${db11g_name}_${schema_name}_${_v_date}.dmp"
            export_data_safirh=1
            echoT "L'export se fera dans ${imp_dp_dir} sous le nom ${f_dmp_data_safirh}"
        else
            choix_dmp "${imp_dp_dir}" "f_dmp_data_safirh"
            export_data_safirh=0
        fi
        f_log_data_safirh="expdp_${f_dmp_data_safirh%.dmp}.log"
    fi    

    # -----------------------------------------------------------------
    # Sélection du dump pour les autres utilisateurs (schema_users)
    # -----------------------------------------------------------------
    if [[ -n "${schema_users}" ]]; then
        boite_titre "Choix du dump pour les autres utilisateurs"
        echoT " "
        echoT "Schémas utilisateurs sélectionnés: ${schema_users}"
        echoT " "
        echoT "Deux possibilités:"
        echoT "  1 - L'export (des utilisateurs ci-dessus) est fait par le script"
        echoT "  2 - Vous choisissez un dump existant dans le répertoire : ${imp_dp_dir}"
        echoT " "
        local _res_users
        _res_users=$(Question_Number "Quelle option choisissez-vous?" "1,2")
        if [[ "${_res_users}" = "1" ]]; then
            f_dmp_users="${db11g_name}_users_${_v_date}.dmp"
            export_users=1
            echoT "L'export des utilisateurs (${schema_users}) se fera dans ${imp_dp_dir} sous le nom ${f_dmp_users}"
        else
            choix_dmp "${imp_dp_dir}" "f_dmp_users"
            export_users=0
        fi
        f_log_users="expdp_${f_dmp_users%.dmp}.log"
    fi
}

function choix_dmp_prod_11g(){
    
    # Si la BD de prod est uqamp sur 04p alors on va chercher le dump sur le NFS de 04t /exports
    # On utilise le nfs pour éviter qu'oracle puisse se connecter sur les serveurs de prod à partir d'un serveur de test 19c
    if [[ ${db11g_name} == "uqamp" ]]; then 
        # 04t contient le nfs sur le répertoire d'export de la prod de uqam
        host11g_nfs_dmp_prod="safirhbd04t"
    else
        # 02t contient tous les nfs sur le répertoire d'export de la prod de tous les établissements sauf uqam
        host11g_nfs_dmp_prod="safirhbd02t"
    fi    
    # 
    nfs_export_prod="/exports/${db11g_name}"
    local _dmp_name
    choix_dmp_remote "_dmp_name"
    
    f_dmp_meta_safirh=${_dmp_name}
    export_meta_safirh=0
    f_dmp_data_safirh=${_dmp_name}
    export_data_safirh=0
}

# Valide et prépare le répertoire d'import Data Pump et l'objet DIRECTORY Oracle correspondant.
# Ajout : va chercher sur la BD 11g source le DIRECTORY_PATH du DIRECTORY EXP_DIR
# Variables attendues :
#   - db_user, db_user_pwd, alias_db_src (pour la connexion 11g)
#   - imp_dp_dir : chemin OS du répertoire (côté 19c) — reste géré comme avant
# Dépendances :
#   - fonctions echoT, fin, boite_titre
# Effets :
#   - définit la variable globale: directory_name (côté 19c)
#   - définit la variable globale: src_exp_dp_dir (EXP_DIR côté 11g)
function valide_datapump_dir() {

    boite_titre "Validation du répertoire d'export + vérification EXP_DIR (source 11g)"

    # 0a) Récupérer EXP_DIR sur la source 11g (obligatoire)
    #     Exemple de connexion fourni par toi, réutilisé ici
    local _out _rc
    src_exp_dp_dir=$(${SQLPLUS} -L -S /nolog <<SQL | sed 's/^[[:space:]]*//; s/[[:space:]]*$//;/^$/d'
set heading off feedback off pages 0 verify off echo off trimout on trimspool on
connect ${db_user}/${db_user_pwd}@${alias_db_src}
select directory_path
  from dba_directories
 where directory_name = 'EXP_DIR';
SQL
)
    _rc=$?
    if [[ $_rc -ne 0 ]]; then
        msg_status 1 "Impossible d'interroger DBA_DIRECTORIES sur la source 11g (code=${_rc})."
        fin; return 1
    fi

    if [[ -z "${src_exp_dp_dir}" ]]; then
        msg_status 1 "Le DIRECTORY ${BOLD}EXP_DIR${RESET} est introuvable sur la BD source 11g (${alias_db_src})."
        echoT "Ce script exige l'existence d'EXP_DIR sur la source. Corrigez et relancez."
        fin; return 1
    fi

    echoT "OK, EXP_DIR (source 11g) pointe vers : ${BLUE}${src_exp_dp_dir}${RESET}"

    # 0b) Définir/ajuster le répertoire local d’export (côté 19c) comme précédemment
    #     (ton script le fixe aussi après ask_dba_credentials ; on garde ce comportement ici)
    boite_titre "Validation du répertoire d'export de la destination 19c"
    imp_dp_dir="/u06/oradata/export/${ORACLE_PDB_SID,,}"

    # 1) Vérifier / créer le répertoire OS (côté 19c)
    if [[ -d "${imp_dp_dir}" ]]; then
        echoT "OK, le répertoire ${imp_dp_dir} existe sur le serveur 19c"
    else
        echoT "Le répertoire '${imp_dp_dir}' n'existe pas."
        read -r -p "Faut-il le créer ? (o/N) " _rep
        _rep="${_rep:-N}"
        if [[ "$_rep" =~ ^[oOyY]$ ]]; then
            mkdir -p -- "${imp_dp_dir}" 2>/dev/null
            if [[ -d "${imp_dp_dir}" ]]; then
                echoT "OK, le répertoire a été créé"
            else
                echoT "ERREUR: échec de création du répertoire '${imp_dp_dir}'."
                fin; return 1
            fi
        else
            echoT "Annulé: le répertoire n'existe pas."
            fin; return 1
        fi
    fi

    # 1b) Canonicaliser le chemin (évite les doublons avec ou sans /, liens symboliques, etc.)
    local _abs_dir
    _abs_dir=$(readlink -f -- "${imp_dp_dir}" 2>/dev/null || printf "%s" "${imp_dp_dir}")

    # 2) Vérifier l'objet DIRECTORY Oracle (côté 19c) pointant sur ce path
    local _path_escaped _sqlout _rc2
    _path_escaped=$(printf "%s" "$_abs_dir" | sed "s/'/''/g")

    _sqlout=$(${SQLPLUS} -L -S "/ as sysdba" <<SQL
SET PAGES 0 FEED OFF VERIFY OFF HEADING OFF ECHO OFF TRIMSPOOL ON LINES 32767
SELECT directory_name
FROM   dba_directories
WHERE  directory_path = q'~${_path_escaped}~'
ORDER  BY directory_name;
SQL
)
    _rc2=$?

    if [[ $_rc2 -ne 0 ]]; then
        echoT "ERREUR: impossible d'interroger DBA_DIRECTORIES sur 19c (code=${_rc2})."
        echoT "$_sqlout"
        fin; return 1
    fi

    # 3) S'il existe déjà, récupérer le nom
    directory_name=$(printf "%s\n" "$_sqlout" | awk 'NF{print; exit}')
    if [[ -n "$directory_name" ]]; then
        echoT "OK, un objet DIRECTORY (19c) existe déjà pour ce chemin : $directory_name"
        return 0
    fi

    # 4) Sinon, créer MIGR_YYYYMMDD_HH24MISS_DIR (avec stratégie anti-collision ORA-00955)
    local _base_name _try_name _create_out _create_rc
    _base_name="MIGR_$(date +%Y%m%d_%H%M%S)_DIR"
    _try_name="$_base_name"

    while :; do
        _create_out=$(${SQLPLUS} -L -S "/ as sysdba" <<SQL
SET PAGES 0 FEED OFF VERIFY OFF HEADING OFF ECHO OFF
WHENEVER SQLERROR EXIT SQL.SQLCODE
CREATE DIRECTORY ${_try_name} AS q'~${_path_escaped}~';
SQL
)
        _create_rc=$?
        if [[ $_create_rc -eq 0 ]]; then
            directory_name="$_try_name"
            echoT "OK, objet DIRECTORY (19c) créé : $directory_name"
            break
        else
            if printf "%s" "$_create_out" | grep -q "ORA-00955"; then
                _try_name="MIGR_$(date +%Y%m%d_%H%M%S)_$(printf "%04d" $((RANDOM%10000)))_DIR"
                continue
            fi
            echoT "ERREUR lors de la création du DIRECTORY 19c :"
            echoT "$_create_out"
            fin; return 1
        fi
    done

    return 0
}

function resume_travail(){
    boite_titre "Résumé des entrées de données"
    echoT "CDB de destination                 : ${BLUE}${ORACLE_SID}${RESET}"
    echoT "PDB de destination                 : ${BLUE}${ORACLE_PDB_SID}${RESET}"
    echoT " "
    echoT "Serveur source                     : ${BLUE}${host11g_name}${RESET}"
    echoT "Instance source                    : ${BLUE}${db11g_name}${RESET}"
    if [ -z $schema_name ]; then
        echoT "***        Aucun schéma Safirh n'a été sélectionné pour migration 19c            ***"
        echoT "*** Il s'agit sûrement de la migration des schémas d'utilisateurs où utilitaires ***"
    else
        echoT "Schéma Safirh à migrer             : ${BLUE}${schema_name}${RESET}" 
        echoT "Schéma Safirh destination          : ${BLUE}${dest_schema_name}${RESET}" 
    fi
    echoT " "
    echoT "Schémas utilitaires à migrer       : ${BLUE}$MIGR_SCHEMAS_UTIL${RESET}"
    echoT "Schémas utilisateurs à migrer      : ${BLUE}$MIGRATION_SCHEMAS${RESET}"
    echoT " "
    echoT "${UNDERLINE}Fichiers Dump existants sélectionnés dans le répertoire ${imp_dp_dir}${RESET} :"
    if [ -n $schema_name ]; then
        if [[ $export_meta_safirh -eq 0 ]]; then
            echoT "Métadata du schéma Safirh          : ${BLUE}${f_dmp_meta_safirh}${RESET}"
        fi
        if [[ $export_data_safirh -eq 0 ]]; then
            echoT "Data schéma Safirh et schémas liés : ${BLUE}${f_dmp_data_safirh}${RESET}"
        fi
    fi
    if [[ $export_users -eq 0 ]]; then
        echoT "Data des schémas des utilisateurs  : ${BLUE}${f_dmp_users}${RESET}"
    fi
    echoT " "
    echoT "${UNDERLINE}Fichiers Dump qui seront créés par le script dans ${imp_dp_dir}${RESET} :"
    if [ -n $schema_name ]; then
        if [[ $export_meta_safirh -eq 1 ]]; then
            echoT "Métadata du schéma Safirh          : ${BLUE}${f_dmp_meta_safirh}${RESET}"
        fi
        if [[ $export_data_safirh -eq 1 ]]; then
            echoT "Data schéma Safirh et schémas liés : ${BLUE}${f_dmp_data_safirh}${RESET}"
        fi
    fi
    if [[ $export_users -eq 1 ]]; then
        echoT "Data des schémas des utilisateurs  : ${BLUE}${f_dmp_users}${RESET}"
    fi
    
}

# Correction de la logique pour le choix 'T' dans select_steps
function select_steps() {
    local _etape=0

    # (ré)initialise le mapping étape -> fonction
    unset STEP_FUNCS 2>/dev/null
    declare -Ag STEP_FUNCS
    declare -Ag STEP_LABELS
    declare -a STEPS
    STEPS=()

    # helper pour ajouter une étape + enregistrer la fonction
    add_step() {
        local label="$1" func="$2"
        ((_etape++))
        printf -v num "%2d" "${_etape}"
        echoT "etape ${num}: ${label}"
        STEP_FUNCS["${_etape}"]="$func"
        STEP_LABELS["${_etape}"]="$label"
        STEPS+=("${_etape}:${func}")
    }

    boite_titre "Sélection des étapes à exécuter" | tee -a "${f_log}"
    echoT "Selectionnez les etapes a executer (entrez leur numero separe par une virgule. ex: 2,3):"

    # --- Étapes conditionnelles liées aux exports ---
    if [[ ${export_meta_safirh:-0} -eq 1 ]]; then
        add_step "Export des métadonnées du schéma ${BLUE}${schema_name}${RESET}" \
                 export_meta_safirh
    fi
    if [[ ${export_data_safirh:-0} -eq 1 ]]; then
        add_step "Export des données (sauf pièces jointes) du schéma ${BLUE}${schema_name}${RESET}" \
                 export_data_safirh
    fi
    if [[ ${export_users:-0} -eq 1 ]]; then
        add_step "Export des données des utilisateurs" \
                 export_users_data
    fi

    # --- Étapes communes / d'infrastructure ---
    add_step "Création des job class CTRL_LOG_HOURLY_JOB_CLASS et CTRL_LOG_DAILY_JOB_CLASS si elles n'existent pas" \
             ensure_ctrl_log_job_classes_and_others

    if [[ ${save_parameters_tables} -eq 1 ]]; then
        add_step "sauvegarde des tables de paramètres du schéma ${dest_schema_name}" \
                 bck_parameters_tables    
    fi
    
    # --- Étapes liées aux schémas Safirh (si sélectionnés) ---
    if [[ -n ${schema_name} ]]; then
        add_step "Destruction des schémas Safirh à importer : ${dest_schema_name},${schema_name_childs}" \
                 drop_schemas_to_import_safirh_and_children
        add_step "Création de l'usager Safirh ${dest_schema_name}" \
                 create_user_safirh_dest
        add_step "Création des rôles qui ont des grants sur les objets de ${schema_name}" \
                 create_roles
    fi

    # --- Étapes liées aux autres schémas (utilitaires / utilisateurs) ---
    if [[ -n ${MIGR_SCHEMAS_UTIL} || -n ${MIGRATION_SCHEMAS} ]]; then
        add_step "Destruction des schémas à importer : ${MIGR_SCHEMAS_UTIL},${MIGRATION_SCHEMAS}" \
                 drop_schemas_to_import_utils_and_users
        add_step "Import des schémas connexes et des schémas des utilisateurs" \
                 import_related_and_users
    fi

    # --- Import metadata Safirh ---
    if [[ -n ${schema_name} ]]; then
        add_step "Import du métadata du schéma safirh ${schema_name}" \
                 import_metadata_safirh
    fi

    # --- CTRL_LOG spécifique ---
    if [[ ${MIGR_SCHEMAS_UTIL} =~ CTRL_LOG ]]; then
        if [[ "${imp_ctrl_log_partiel}" == "1" ]]; then
            add_step "Import partiel du schéma CTRL_LOG" \
                     import_schema_ctrl_log
        else
            add_step "Import du schéma CTRL_LOG" \
                     import_schema_ctrl_log
        fi
    fi

    # --- BIUQ spécifique ---
    if [[ ${MIGR_SCHEMAS_UTIL} =~ BIUQ ]]; then
        add_step "Import partiel du schéma BIUQ" \
                 import_schema_biuq
    fi

    # --- BIUQ spécifique ---
    if [[ ${MIGR_SCHEMAS_UTIL} =~ TABLEAU ]]; then
        add_step "Import partiel du schéma TABLEAU" \
                 import_schema_tableau
    fi

    # --- Préparation / migration coeur ---
    add_step "Préparation des objets requis pour les tâches de migration dans le schéma ${db_user19c}" \
             prepare_required_objects_in_db_user19c
    add_step "Drop les indexes Oracle Text (du moins ceux qui ont réussi à être importés)" \
             drop_oracle_text_indexes
    add_step "Exécution du PL/SQL pour changer la définition des VARCHAR2 de BYTE en CHAR" \
             convert_varchar2_byte_to_char
    #add_step "Autorise ${db_user19c} à se connecter en proxy sur ${dest_schema_name}" \
             #allow_proxy_connect_db_user19c_to_dest
    add_step "Exécution de plsql_json_orig.sql en étant connecté avec ${dest_schema_name}" \
             run_plsql_json_as_dest_schema
    add_step "Désactivation des triggers de ${dest_schema_name}" \
             disable_triggers_dest
    add_step "Désactivation des FK de ${dest_schema_name}" \
             disable_fk_dest            
    add_step "Import des données de ${schema_name} dans ${dest_schema_name}" \
             import_data_from_schema_to_dest
    add_step "Recompilation (utlrp.sql) et calcul des stats du dictionnaire" \
             recompile_and_gather_dict_stats
    add_step "Réactivation des triggers de ${dest_schema_name}" \
             enable_triggers_dest
    add_step "Réactivation des FK de ${dest_schema_name}" \
             enable_fk_dest
#    add_step "Calcul des stats du schéma ${dest_schema_name}" \
#             gather_stats_dest_schema
    add_step "Création des index Oracle Text" \
             create_oracle_text_indexes
    add_step "Migration des network ACLs en Host ACEs" \
             migrate_network_acls_to_host_aces
    add_step "Création du wokspace Apex" \
             create_apex_workspace
#    add_step "Création des vues matérialisées (les scripts doivent être présents sur le serveur)" \
#             create_materialized_views
    if [[ ${save_parameters_tables} -eq 1 ]]; then
        add_step "Restore des tables de paramètres du schéma ${dest_schema_name}" \
                 restore_parameters_tables    
    fi
    
    # La copie des informations de rafraîchissement de se fait pas pour les envoronnements de prod
    if [[ -n "${schema_name}" && "${schema_name}" != *PROD ]]; then
    
        add_step "Mise à jour de la date de rafraîchissement 11G dans ${dest_schema_name}.GSPAS_VAL_CLI" \
             sync_gspas_val_cli_forms_title
    fi
    
    add_step "Retrait du rôle DBA de ${dest_schema_name}" \
             revoke_dba_safirh

    # --- Finalisation sélection utilisateur ---
    nb_steps=${_etape}
    all_steps=$(seq -s, 1 "${nb_steps}")

    echoT "Entrez 'T' pour executer l'ensemble des etapes."
    read -r user_input

    # Normalisation de l'entrée (suppression des espaces)
    user_input="${user_input//[[:space:]]/}"

    # 'T' => toutes les étapes
    if [[ "${user_input^^}" == "T" ]]; then
        user_input="${all_steps}"
    fi

    if [[ -z "${user_input}" ]]; then
        echoT "Entrée invalide. Veuillez saisir la liste des étapes à exécuter séparées par des virgules "
        echoT " ou alors 'T' pour toutes les étapes."
        return 1
    fi

    # Validation robuste : chaque token doit être un entier entre 1 et nb_steps
    IFS=',' read -r -a _tokens <<< "${user_input}"
    local ok=1 tok
    for tok in "${_tokens[@]}"; do
        if ! [[ "$tok" =~ ^[0-9]+$ ]]; then
            ok=0; break
        fi
        if (( tok < 1 || tok > nb_steps )); then
            ok=0; break
        fi
    done

    if (( ok )); then
        selected_steps="${user_input}"
    else
        echoT "Entrée invalide. Veuillez saisir la liste des étapes à exécuter séparées par des virgules "
        echoT " ou alors 'T' pour toutes les étapes."
        return 1
    fi
}

# Exécute les étapes sélectionnées (en ordre numérique croissant des numéros d’étape)
function run_selected_steps() {
    # On retire les espaces de la sélection des étapes pour avoir un vrai csv
    local steps_csv="${selected_steps//[[:space:]]/}"
    if [[ -z "$steps_csv" ]]; then
        echoT "${RED}ERREUR${RESET} : aucune étape sélectionnée (selected_steps est vide)."
        return 1
    fi

    # Parse, trier numériquement et dédupliquer les numéros d'étapes
    IFS=',' read -r -a _steps_raw <<< "$steps_csv"
    mapfile -t _steps < <(printf "%s\n" "${_steps_raw[@]}" | sed '/^$/d' | sort -n -u)

    # Validation : chaque numéro doit exister dans le mapping
    local s ok=1
    for s in "${_steps[@]}"; do
        if [[ -z "${STEP_FUNCS[$s]:-}" ]]; then
            echoT "${RED}ERREUR${RESET} : l'étape ${s} n'existe pas dans le mapping."
            ok=0
        fi
    done
    (( ok == 0 )) && return 1

    # Exécution séquentielle en ordre croissant
    local rc=0 started ended dur fn label
    for s in "${_steps[@]}"; do
        fn="${STEP_FUNCS[$s]}"
        label="${STEP_LABELS[$s]:-${fn}}"
        printf -v sn "%2d" "$s"
        boite_titre "Exécution de l'étape ${sn}"
        boite_soustitre "${label}" | tee -a ${f_log}
        echoT " "
        echoT "    Fonction: ${fn}()"
        echoT " "
        started=$(date +%s)

        if ! declare -F -- "$fn" >/dev/null 2>&1; then
            ended=$(date +%s)
            dur=$((ended - started))
            analyse_rslt "$s" "$fn" 1 0 "$label" "${dur}s"
            echoT "---"
            continue
        fi

        "$fn"
        rc=${PIPESTATUS[0]}

        ended=$(date +%s)
        dur=$((ended - started))

        # Enregistre le résultat (ne stoppe plus)
        analyse_rslt "$s" "$fn" "$rc" 0 "$label" "${dur}s"
        echoT "---"
    done

    echoT "Toutes les étapes sélectionnées ont été exécutées et en voici le résultat:"
    print_steps_report
    echoT "Vérifiez le log pour valider les erreurs"
    
    return 0
}

# Fonction générique d'export Datapump exécutée sur le serveur 11g via SSH
# Args:
#   $1 : nom de la variable qui contient le nom du dump (ex: f_dmp_meta_safirh)
#   $2 : nom de la variable qui contient le nom du log expdp (ex: f_log_meta_safirh)
#   $3 : nom de la variable qui contient la commande distante (remote_cmd)
#   $4 : (optionnel) étiquette pour les logs/analyse (ex: export_meta_safirh)
# Le fichier est ensuite bougé via rsync sur la destination
function export_generic_11g() {
    local dump_var="$1" log_var="$2" rcmd_var="$3" label="${4:-export_generic_11g}"
    if [[ -z "$dump_var" || -z "$log_var" || -z "$rcmd_var" ]]; then
        echoT "${RED}ERREUR${RESET} : paramètres manquants à export_generic_11g (dump_var/log_var/rcmd_var)."
        return 1
    fi

    # Indirections pour récupérer les valeurs
    local dump_name="${!dump_var}"
    local log_name="${!log_var}"
    local remote_cmd="${!rcmd_var}"

    if [[ -z "$dump_name" || -z "$log_name" || -z "$remote_cmd" ]]; then
        echoT "${RED}ERREUR${RESET} : dump/log/commande distante non définis (dump='${dump_name}' log='${log_name}')."
        return 1
    fi

    echoT "Commande distante : ssh oracle@${host11g_name} \"${remote_cmd}\""

    # Exécuter à distance
    ssh -o BatchMode=yes -o ConnectTimeout=15 oracle@"${host11g_name}" "${remote_cmd}"
    local rslt=$?

    #analyse_rslt "${label}" ${rslt} 0

    # Copier le dump et log -> répertoire local 19c via rsync (SSH, progression)
    #   src_exp_dp_dir : chemin côté 11g (sur ${host11g_name})
    #   imp_dp_dir     : répertoire local cible (non-NFS)
    if [[ -z "${src_exp_dp_dir:-}" || -z "${imp_dp_dir:-}" ]]; then
        echoT "${YELLOW}ATTENTION${RESET} : src_exp_dp_dir ou imp_dp_dir non défini — copie impossible."
    else
        mkdir -p -- "${imp_dp_dir}" 2>/dev/null || true

        local moved_any=0
        local f rsrc
        for f in "${dump_name}" "${log_name}"; do
            rsrc="${src_exp_dp_dir}/${f}"

            # Vérifie l'existence côté source (serveur 11g)
            if ssh -o BatchMode=yes -o ConnectTimeout=15 oracle@"${host11g_name}" "test -f \"$rsrc\""; then
                echoT "Transfert rsync de ${BLUE}${rsrc}${RESET} -> ${BLUE}${imp_dp_dir}/${f}${RESET}"
                # -a : archive | -v : verbeux | --progress : progression | -h : tailles lisibles
                # --partial : reprend si interrompu | --inplace : écrit en place | --remove-source-files : supprime la source si transfert OK
                rsync -a -v --progress -h --partial --inplace --remove-source-files \
                      -e "ssh -o BatchMode=yes -o ConnectTimeout=15" \
                      "oracle@${host11g_name}:${rsrc}" "${imp_dp_dir}/"
                _rc=$?

                if [[ $_rc -eq 0 ]]; then
                    (( moved_any++ ))
                else
                    echoT "${YELLOW}ATTENTION${RESET} : échec rsync pour ${rsrc} (rc=${_rc})."
                fi
            else
                echoT "${YELLOW}ATTENTION${RESET} : fichier introuvable côté source (SSH) : ${rsrc}"
            fi
        done

        (( moved_any > 0 )) && echoT "Fichiers transférés vers ${imp_dp_dir}."
    fi

    # Ajouter le contenu du log à f_log si disponible
    if [[ -f "${imp_dp_dir}/${log_name}" ]]; then
        echo " "  >> "${f_log}"
        echo "***************************" >> "${f_log}"
        echo "***   Log de l'export   ***" >> "${f_log}"
        echo "***************************" >> "${f_log}"
        echo " "  >> "${f_log}"
        cat "${imp_dp_dir}/${log_name}" >> "${f_log}"
    else
        echoT "${YELLOW}ATTENTION${RESET} : log introuvable à ${imp_dp_dir}/${log_name}"
    fi

    # Vérifier les erreurs ORA- dans le log et demander confirmation pour continuer
    if [[ -f "${imp_dp_dir}/${log_name}" ]] && grep -E -q 'ORA-[0-9]+' "${imp_dp_dir}/${log_name}"; then
        echoT "${YELLOW}ATTENTION${RESET} : des erreurs ORA- ont été détectées dans ${imp_dp_dir}/${log_name}."
        continue_execution "Des erreurs ORA- ont été détectées dans ${log_name}. Souhaitez-vous continuer malgré ces erreurs?"
    fi

    return ${rslt}
}

# Spécifique : export des métadonnées Safirh
function export_meta_safirh() {
    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "  Serveur 11g      : ${host11g_name}"
    echoT "  Instance 11g     : ${db11g_name}"
    echoT "  Fichier d'export : ${src_exp_dp_dir}/${f_dmp_meta_safirh} (source)"
    echoT "  Fichier de log   : ${src_exp_dp_dir}/${f_log_meta_safirh} (source)"
    echoT "  Destination      : ${imp_dp_dir} (déplacement post-export)"
    echoT "------------------------------------------------------------------"
    echoT " "
    
    # Construire la commande distante : sourcer l'environnement 11g puis expdp
    remote_cmd="source \\${HOME}/${db11g_name}bd.sh; expdp \"'/ as sysdba'\" DIRECTORY=EXP_DIR DUMPFILE='${f_dmp_meta_safirh}' LOGFILE='${f_log_meta_safirh}' SCHEMAS='${schema_name}' CONTENT=METADATA_ONLY FLASHBACK_TIME=\"${flashback_time}\""

    # Appel générique
    export_generic_11g "f_dmp_meta_safirh" "f_log_meta_safirh" "remote_cmd" "export_meta_safirh"
}

function export_data_safirh() {
    # Export des données (sauf pièces jointes) du schéma Safirh via expdp exécuté SUR LE SERVEUR 11g

    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "  Serveur 11g      : ${host11g_name}"
    echoT "  Instance 11g     : ${db11g_name}"
    echoT "  Fichier d'export : ${src_exp_dp_dir}/${f_dmp_data_safirh} (source)"
    echoT "  Fichier de log   : ${src_exp_dp_dir}/${f_log_data_safirh} (source)"
    echoT "  Destination      : ${imp_dp_dir} (déplacement post-export)"
    echoT "------------------------------------------------------------------"

    local parfile="${d_par}/exp_safirh_data_sans_pj.par"

    # S'assurer que le répertoire existe sur le serveur 11g
    echoT "Création du répertoire ${d_par} sur ${host11g_name} si inexistant"
    ssh -o BatchMode=yes -o ConnectTimeout=15 oracle@"${host11g_name}" "mkdir -p '${d_par}'"
    if [[ $? -ne 0 ]]; then
        echoT "${RED}ERREUR${RESET} : échec de la création du répertoire ${d_par} sur ${host11g_name}"
        return 1
    fi

    # Copier le parfile sur le serveur 11g (même répertoire ${d_par})
    echoT "Copie du parfile ${parfile} vers ${host11g_name}:${parfile}"
    scp -q "${parfile}" oracle@"${host11g_name}:${parfile}"
    if [[ $? -ne 0 ]]; then
        echoT "${RED}ERREUR${RESET} : échec de la copie du parfile sur ${host11g_name}"
        return 1
    fi

    # Construire la commande distante expdp
    remote_cmd="source \$HOME/${db11g_name}bd.sh; expdp \"'/ as sysdba'\" \
        DIRECTORY=EXP_DIR \
        DUMPFILE='${f_dmp_data_safirh}' \
        LOGFILE='${f_log_data_safirh}' \
        SCHEMAS='${schema_name}' \
        CONTENT=DATA_ONLY \
        FLASHBACK_TIME=\"${flashback_time}\" \
        PARFILE='${parfile}'"

    echoT "Commande distante : ssh oracle@${host11g_name} \"${remote_cmd}\""

    # Appel générique
    export_generic_11g "f_dmp_data_safirh" "f_log_data_safirh" "remote_cmd" "export_data_safirh"

#    ssh -o BatchMode=yes -o ConnectTimeout=15 oracle@"${host11g_name}" "${remote_cmd}"
#    rslt=$?
#
#    analyse_rslt "export_data_safirh_old" ${rslt} 0
#
#    echo " "  >> ${f_log}
#    echo "***************************" >> ${f_log}
#    echo "***   Log de l'export   ***" >> ${f_log}
#    echo "***************************" >> ${f_log}
#    echo " "  >> ${f_log}
#
#    # Le répertoire NFS n'étant pas partagé, on déplace le dump et le log du src_exp_dp_dir vers imp_dp_dir
#    if [[ -f "${src_exp_dp_dir}/${f_log_data_safirh}" ]]; then
#        mv -f -- "${src_exp_dp_dir}/${f_log_data_safirh}" "${imp_dp_dir}/"
#    fi
#    if [[ -f "${src_exp_dp_dir}/${f_dmp_data_safirh}" ]]; then
#        mv -f -- "${src_exp_dp_dir}/${f_dmp_data_safirh}" "${imp_dp_dir}/"
#    fi
#
#    # Vérification d'erreurs ORA- dans le log
#    if grep -q "ORA-" "${imp_dp_dir}/${f_log_data_safirh}"; then
#        continue_execution "Des erreurs ORA- ont été détectées dans le log ${f_log_data_safirh}. Voulez-vous continuer ?" || return 1
#    fi
#
#    # Ajout du contenu du log expdp dans le log principal
#    if [[ -f "${imp_dp_dir}/${f_log_data_safirh}" ]]; then
#        cat "${imp_dp_dir}/${f_log_data_safirh}" >> "${f_log}"
#    fi
}

function export_users_data() {
    echoT "Export des données des utilisateurs de ${db11g_name}"

    # Concaténer MIGRATION_SCHEMAS, MIGR_SCHEMAS_UTIL et schema_name_childs -> exp_schemas_list
    exp_schemas_list=""
    for v in "$MIGRATION_SCHEMAS" "$MIGR_SCHEMAS_UTIL" "$schema_name_childs"; do
        if [[ -n "$v" ]]; then
            if [[ -z "$exp_schemas_list" ]]; then
                exp_schemas_list="$v"
            else
                exp_schemas_list="$exp_schemas_list,$v"
            fi
        fi
    done
    exp_schemas_list=$(echo "$exp_schemas_list" | sed 's/,,*/,/g; s/^,//; s/,$//')

    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "  Fichier d'export : ${src_exp_dp_dir}/${f_dmp_users} (source)"
    echoT "  Fichier de log   : ${src_exp_dp_dir}/${f_log_users} (source)"
    echoT "  Destination      : ${imp_dp_dir} (déplacement post-export)"
    echoT "------------------------------------------------------------------"
    echoT " "

    # Construire la commande distante : sourcer l'environnement 11g puis expdp des schémas utilisateurs
    remote_cmd="source \${HOME}/${db11g_name}bd.sh; expdp \"'/ as sysdba'\" DIRECTORY=EXP_DIR DUMPFILE='${f_dmp_users}' LOGFILE='${f_log_users}' SCHEMAS='${exp_schemas_list}' FLASHBACK_TIME=\"${flashback_time}\""

    # Appel générique
    export_generic_11g "f_dmp_users" "f_log_users" "remote_cmd" "export_users_data"
}

function ensure_ctrl_log_job_classes_and_others() {
    echoT "Vérification/Création des job class CTRL_LOG_* + fonction VERIF_PASS_UQ et profile SAF_DEV_PROF"

    # 1) Job classes CTRL_LOG_*
    _out=$(${SQLPLUS} -L -S / as sysdba <<SQL
set serveroutput on size 1000000
set feedback off heading off verify off pages 0 trimspool on
WHENEVER SQLERROR EXIT SQL.SQLCODE
DECLARE
  n NUMBER;
BEGIN
  -- CTRL_LOG_HOURLY_JOB_CLASS
  SELECT COUNT(*) INTO n
    FROM dba_scheduler_job_classes
   WHERE job_class_name = 'CTRL_LOG_HOURLY_JOB_CLASS';
  IF n = 0 THEN
    dbms_scheduler.create_job_class(
      job_class_name  => 'CTRL_LOG_HOURLY_JOB_CLASS',
      logging_level   => sys.dbms_scheduler.logging_runs,
      log_history     => 1440,
      comments        => 'Vérification des erreurs de login');
    dbms_output.put_line('CREATED: CTRL_LOG_HOURLY_JOB_CLASS');
  ELSE
    dbms_output.put_line('EXISTS : CTRL_LOG_HOURLY_JOB_CLASS');
  END IF;
  -- CTRL_LOG_DAILY_JOB_CLASS
  SELECT COUNT(*) INTO n
    FROM dba_scheduler_job_classes
   WHERE job_class_name = 'CTRL_LOG_DAILY_JOB_CLASS';
  IF n = 0 THEN
    dbms_scheduler.create_job_class(
      job_class_name  => 'CTRL_LOG_DAILY_JOB_CLASS',
      logging_level   => sys.dbms_scheduler.logging_runs,
      log_history     => 60,
      comments        => 'Travaux de maintenance sur CTRL_LOG');
    dbms_output.put_line('CREATED: CTRL_LOG_DAILY_JOB_CLASS');
  ELSE
    dbms_output.put_line('EXISTS : CTRL_LOG_DAILY_JOB_CLASS');
  END IF;
END;
/
exit
SQL
)
    rc=$?
    [[ -n "$_out" ]] && echoT "$_out"
    #analyse_rslt "ensure_ctrl_log_job_classes_and_others (job classes)" $rc 0
    (( rc != 0 )) && return $rc

    # 2) Exécution de la fonction de vérification de mot de passe dans le PDB
    local _func_file="${d_sql}/function_VERIF_PASS_UQ.sql"
    if [[ ! -f "${_func_file}" ]]; then
        echoT "${RED}ERREUR${RESET} : fichier introuvable : ${_func_file}"
        return 1
    fi

    _out_fn=$(${SQLPLUS} -L -S / as sysdba <<SQL
set pages 0 feedback on heading off verify off trimspool on
WHENEVER SQLERROR EXIT SQL.SQLCODE
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};
@"${_func_file}"
EXIT
SQL
)
    rc_fn=$?
    [[ -n "$_out_fn" ]] && echoT "$_out_fn"
    #analyse_rslt "ensure_ctrl_log_job_classes_and_others (VERIF_PASS_UQ)" $rc_fn 0
    (( rc_fn != 0 )) && return $rc_fn

    # 3) Création du profile SAF_DEV_PROF s'il n'existe pas (dans le PDB)
    _out_prof=$(${SQLPLUS} -L -S / as sysdba <<SQL
set serveroutput on size 1000000
set feedback off heading off verify off pages 0 trimspool on
WHENEVER SQLERROR EXIT SQL.SQLCODE

DECLARE
  n NUMBER;
BEGIN
  EXECUTE IMMEDIATE 'ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID}';
  SELECT COUNT(*) INTO n FROM dba_profiles WHERE profile = 'SAF_DEV_PROF';
  IF n = 0 THEN
    -- Utilise exactement les limites demandées (les valeurs jour peuvent être des expressions)
    EXECUTE IMMEDIATE '
      CREATE PROFILE "SAF_DEV_PROF"
        LIMIT
             COMPOSITE_LIMIT UNLIMITED
             SESSIONS_PER_USER UNLIMITED
             CPU_PER_SESSION UNLIMITED
             CPU_PER_CALL UNLIMITED
             LOGICAL_READS_PER_SESSION UNLIMITED
             LOGICAL_READS_PER_CALL UNLIMITED
             IDLE_TIME 120
             CONNECT_TIME UNLIMITED
             PRIVATE_SGA UNLIMITED
             FAILED_LOGIN_ATTEMPTS 10
             PASSWORD_LIFE_TIME UNLIMITED
             PASSWORD_REUSE_TIME 86400/86400
             PASSWORD_REUSE_MAX 4
             PASSWORD_VERIFY_FUNCTION VERIF_PASS_UQ
             PASSWORD_LOCK_TIME 86400/86400
             PASSWORD_GRACE_TIME UNLIMITED
    ';
    dbms_output.put_line('CREATED: SAF_DEV_PROF');
  ELSE
    dbms_output.put_line('EXISTS : SAF_DEV_PROF');
  END IF;
END;
/
EXIT
SQL
)
    rc_prof=$?
    [[ -n "$_out_prof" ]] && echoT "$_out_prof"
    #analyse_rslt "ensure_ctrl_log_job_classes_and_others (SAF_DEV_PROF)" $rc_prof 0
    (( rc_prof != 0 )) && return $rc_prof

    return 0
}

# --- Helper: attendre qu'aucune session ne soit connectée pour une liste d'utilisateurs ---
function wait_no_sessions_for_users() {
    # usage: wait_no_sessions_for_users USER1 USER2 ...
    local _users=("$@") u list_in_sql out
    [[ ${#_users[@]} -gt 0 ]] || return 0

    # construit la liste pour l'IN() SQL
    for u in "${_users[@]}"; do
        list_in_sql+="'${u^^}',"
    done
    list_in_sql=${list_in_sql%,}

    while :; do
        out=$(${SQLPLUS} -L -S "/ as sysdba" <<SQL
whenever sqlerror exit sql.sqlcode;
set heading on feedback off pages 500 lines 300 trimspool on
col USERNAME format a20
col MACHINE  format a30
col PROGRAM  format a40
col LOGON    format a16
select inst_id, sid, serial#, username, status, machine, program,
       to_char(logon_time,'YYYY-MM-DD HH24:MI') LOGON
  from gv\$session
 where username in (${list_in_sql})
 order by username, inst_id, sid;
SQL
) || { echoT "ERREUR: échec de la vérification des sessions (${SQLPLUS})"; return 1; }

        # S'il n'y a plus de lignes utiles, on sort
        if [[ -z "$(printf "%s" "$out" | awk 'NR>2 && $0!~/^[- ]+$/ {print; exit}')" ]]; then
            echoT "OK: aucune session connectée pour: ${_users[*]}"
            break
        fi

        echoT "ATTENTION: Des sessions sont encore connectées sur: ${_users[*]}"
        echoT "Liste des sessions à fermer (inst_id,sid,serial#,user,status,machine,program,logon):"
        echoT "$out"
        echoT "Ne mettez PAS le PDB en mode restreint : le script nécessite une connexion avec ${dest_schema_name}."
        read -r -p "Fermez ces connexions puis appuyez sur Entrée pour revérifier... " _
    done
}

function bck_parameters_tables() {

    # Sauvegarde des tables de paramètres du schéma ${dest_schema_name}

    {
        ${SQLPLUS} -L -S "/ as sysdba" \
            @"${d_sql}/sauvegarde_parametres.sql" "${dest_schema_name}" \
            | tee -a "${f_log}"
    } 2>&1
    rc=${PIPESTATUS[0]}
    
    #analyse_rslt "bck_parameters_tables (sauvegarde paramètres)" "${rc}" 0
}

function drop_schemas_to_import_safirh_and_children() {
    # --- Validation préalable: aucune session connectée sur les utilisateurs visés ---
    local _targets=()

    if [[ -n "${schema_name:-}" ]]; then
        _targets+=("${schema_name}")
    fi

    # schémas enfants/app potentiels (CSV)
    if [[ -n "${MIGRATION_SCHEMAS:-}" ]]; then
        IFS=',' read -r -a __arr <<< "${MIGRATION_SCHEMAS}"
        _targets+=("${__arr[@]}")
    fi

    # schéma renommé éventuel
    if [[ -n "${dest_schema_name:-}" ]]; then
        _targets+=("${dest_schema_name}")
    fi

    if ((${#_targets[@]})); then
        declare -A __seen
        local __uniq=()
        local x

        for x in "${_targets[@]}"; do
            if [[ -n "$x" && -z "${__seen[$x]}" ]]; then
                __seen[$x]=1
                __uniq+=("$x")
            fi
        done

        wait_no_sessions_for_users "${__uniq[@]}" || return 1
    fi

    # Construit la liste (unique) des schémas à supprimer : dest + enfants CSV
    local _all="" _csv="${dest_schema_name_childs:-}"

    if [[ -n "${dest_schema_name:-}" ]]; then
        _all="${dest_schema_name}"
    fi

    if [[ -n "${_csv}" ]]; then
        if [[ -n "${_all}" ]]; then
            _all="${_all},${_csv}"
        else
            _all="${_csv}"
        fi
    fi

    # Rien à faire ?
    if [[ -z "${_all}" ]]; then
        echoT "Aucun schéma destination à supprimer (dest_schema_name/dest_schema_name_childs vides)."
        return 0
    fi

    # Normalise : split, trim, uppercase, déduplication
    IFS=',' read -r -a _arr <<< "${_all}"
    declare -A _seen=()
    local _list=()
    local x t

    for x in "${_arr[@]}"; do
        t=$(echo "$x" | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')
        if [[ -z "$t" ]]; then
            continue
        fi
        t=$(echo "$t" | tr '[:lower:]' '[:upper:]')
        if [[ -n "${_seen[$t]:-}" ]]; then
            continue
        fi
        _seen[$t]=1
        _list+=("$t")
    done

    if ((${#_list[@]} == 0)); then
        echoT "Aucun schéma valide à supprimer."
        return 0
    fi

    echoT "***"
    echoT "Cible : CDB ${ORACLE_SID} / PDB ${ORACLE_PDB_SID}"
    echoT "Schémas potentiellement à supprimer : ${_list[*]}"
    echoT "***"

    local rc_all=0
    local ans
    local sch
    local exists
    local _out
    local rc

    for sch in "${_list[@]}"; do
        # 1) Vérifier si le schéma existe dans le PDB
        exists=$(${SQLPLUS} -L -S / as sysdba <<SQL
SET FEEDBACK OFF HEADING OFF PAGES 0 VERIFY OFF
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};
SELECT COUNT(*) FROM dba_users WHERE username = UPPER('${sch}');
EXIT;
SQL
)
        exists=$(echo "$exists" | tr -d '[:space:]')

        if [[ "$exists" != "0" && "$exists" != "1" ]]; then
            echoT "${YELLOW}ATTENTION${RESET} : impossible de déterminer l'existence du schéma ${sch} (valeur lue='${exists}')."
            # on n'arrête pas pour autant
        fi

        if [[ "$exists" == "0" ]]; then
            echoT "Schéma absent : ${sch}"
            continue
        fi

        # 2) Demander la confirmation uniquement si le schéma existe
        Question_YesNo "Voulez-vous vraiment supprimer le schéma ${BLUE}${sch}${RESET} sur le CDB ${BLUE}${ORACLE_SID}${RESET} et le PDB ${BLUE}${ORACLE_PDB_SID}${RESET} ? " ans
        if [[ "$ans" != "Y" ]]; then
            echoT "Suppression de ${sch} annulée par l'utilisateur."
            continue
        fi

        # 3) Drop dans le PDB (réel, avec CASCADE)
        _out=$(${SQLPLUS} -L -S / as sysdba <<SQL
set serveroutput on size 1000000
set feedback off heading off verify off pages 0 trimspool on
WHENEVER SQLERROR EXIT SQL.SQLCODE
alter session set container = ${ORACLE_PDB_SID};
DECLARE
  n NUMBER;
BEGIN
  SELECT COUNT(*) INTO n FROM dba_users WHERE username = UPPER('${sch}');
  IF n > 0 THEN
    EXECUTE IMMEDIATE 'DROP USER '||UPPER('${sch}')||' CASCADE';
    dbms_output.put_line('DROPPED:'||UPPER('${sch}'));
  ELSE
    dbms_output.put_line('MISSING:'||UPPER('${sch}'));
  END IF;
END;
/
exit
SQL
)
        rc=$?
        if [[ -n "$_out" ]]; then
            echoT "$_out"
        fi

        if (( rc != 0 )); then
            echoT "${RED}ERREUR${RESET} : échec du DROP USER ${sch} (rc=${rc})."
            rc_all=$rc
            # Si tu préfères arrêter au premier échec :
            # return $rc
        else
            echoT "${GREEN}OK${RESET} : suppression traitée pour ${sch}."
        fi
    done

    return $rc_all
}

# Récupère le mot de passe du schéma migré (dest_schema_name) sur le serveur 11g.
# Source: /home/oracle/admin/environnement/${dest_schema_name,,}/properties.sh
# Le mot de passe est lu après "PWD=" et stocké dans la variable globale: dest_schema_pwd
# En cas d'échec: dest_schema_pwd="PassToBeChanged"
function get_schema_pwd() {

    local label="${1:-get_schema_pwd}"

    # Garde-fous minimaux
    if [[ -z "${dest_schema_name:-}" ]]; then
        echoT "${YELLOW}ATTENTION${RESET} : dest_schema_name non défini — mot de passe par défaut utilisé."
        dest_schema_pwd="PassToBeChanged"
        return 1
    fi
    if [[ -z "${host11g_name:-}" ]]; then
        echoT "${YELLOW}ATTENTION${RESET} : host11g_name non défini — mot de passe par défaut utilisé."
        dest_schema_pwd="PassToBeChanged"
        return 1
    fi

    local props_dir="/home/oracle/admin/environnement/${dest_schema_name,,}"
    local props_file="${props_dir}/properties.sh"

    # Extraction stricte:
    # - ne garde que les lignes qui commencent par PWD=
    # - prend la première occurrence
    # - enlève le "PWD="
    # - trim espaces
    # - enlève guillemets simples/doubles éventuels autour de la valeur
    local pwd
    pwd=$(ssh -o BatchMode=yes -o ConnectTimeout=15 oracle@"${host11g_name}" "
        test -r '${props_file}' &&
        awk -F= '
            /^[[:space:]]*PWD[[:space:]]*=/ {
                val=\$0
                sub(/^[[:space:]]*PWD[[:space:]]*=[[:space:]]*/, \"\", val)
                gsub(/^[[:space:]]+|[[:space:]]+$/, \"\", val)
                gsub(/^\"|\"$/, \"\", val)
                gsub(/^'\''|'\''$/, \"\", val)
                print val
                exit
            }
        ' '${props_file}'
    " 2>/dev/null)
    local rc=$?

    # Nettoyage local (au cas où)
    pwd="$(printf "%s" "$pwd" | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"

    if [[ $rc -ne 0 || -z "$pwd" ]]; then
        echoT "${YELLOW}ATTENTION${RESET} : impossible de lire PWD dans ${props_file} sur ${host11g_name} — mot de passe = PassToBeChanged"
        dest_schema_pwd="PassToBeChanged"
        #analyse_rslt "${label}" 1 1
        return 1
    fi
    echoT "Mot de passe de l'utilisateur ${dest_schema_name} récupéré avec succès!"
    dest_schema_pwd="$pwd"

    return 0
}

#Fonction de Création de l'usager Safirh ${dest_schema_name}
function create_user_safirh_dest() {

        echoT "tablespace du schéma de dest       : ${BLUE}${tbs_dest_schema_name}${RESET}" 
        echoT "Schéma Safirh destination          : ${BLUE}${dest_schema_name}${RESET}" 

    if [[ -z "${dest_schema_name:-}" || -z "${tbs_dest_schema_name:-}" ]]; then
        echoT "${RED}ERREUR${RESET} : dest_schema_name ou tbs_dest_schema_name non défini."
        return 1
    fi
    
    # On récupère le mot de passe sur le serveur 11g où se trouve la source des données
    # Si le mot de passe n'est pas trouvé alors il sera mis à une valeur par défaut: PassToBeChanged
    get_schema_pwd
    
    local tmp_sql
    tmp_sql="$(mktemp /tmp/create_user_${dest_schema_name}_XXXX.sql)"

    cat > "${tmp_sql}" <<SQL
set echo on feedback on verify off heading off pages 0 trimspool on
WHENEVER SQLERROR EXIT SQL.SQLCODE

-- On travaille dans le bon PDB
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};

-- Création de l'usager et TBS par défaut/temp
CREATE USER "${dest_schema_name}"
  IDENTIFIED BY "${dest_schema_pwd}"
  DEFAULT TABLESPACE "${tbs_dest_schema_name}"
  TEMPORARY TABLESPACE "TEMP";

-- GRANTs au schéma de destination (au lieu de la valeur fixe ENAP19C)
GRANT "DEVELOP"                              TO "${dest_schema_name}";
GRANT CREATE TABLE                           TO "${dest_schema_name}";
GRANT SELECT  ON SYS.V_\$SESSION             TO "${dest_schema_name}";
GRANT SELECT  ON SYS.V_\$LOCKED_OBJECT       TO "${dest_schema_name}";
GRANT SELECT  ON SYS.USER_OBJECTS            TO "${dest_schema_name}";
GRANT EXECUTE ON SYS.DBMS_LOB                TO "${dest_schema_name}";
GRANT EXECUTE ON SYS.UTL_TCP                 TO "${dest_schema_name}";
GRANT EXECUTE ON SYS.UTL_HTTP                TO "${dest_schema_name}";
GRANT EXECUTE ON SYS.UTL_FILE                TO "${dest_schema_name}";
GRANT EXECUTE ON SYS.DBMS_UTILITY            TO "${dest_schema_name}";
GRANT EXECUTE ON SYS.UTL_SMTP                TO "${dest_schema_name}";
GRANT EXECUTE ON SYS.DBMS_APPLICATION_INFO   TO "${dest_schema_name}";
GRANT EXECUTE ON SYS.DBMS_JOB                TO "${dest_schema_name}";
GRANT EXECUTE ON SYS.DBMS_CRYPTO             TO "${dest_schema_name}";
GRANT EXECUTE ON SYS.DBMS_RANDOM             TO "${dest_schema_name}";
GRANT EXECUTE ON SYS.HTP                     TO "${dest_schema_name}";
GRANT EXECUTE ON SYS.OWA_UTIL                TO "${dest_schema_name}";
GRANT EXECUTE ON CTXSYS.CTX_DDL              TO "${dest_schema_name}";
GRANT EXECUTE ON CTXSYS.CTX_DOC              TO "${dest_schema_name}";

-- Pour permettre la création de vues matérialisées
GRANT DBA TO "${dest_schema_name}";

EXIT
SQL
    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "Création de l'utilisateur ${BLUE}${dest_schema_name}${RESET} dans PDB ${BLUE}${ORACLE_PDB_SID}${RESET}"
    echoT "TBS par défaut: ${tbs_dest_schema_name}"
    echoT "Script: ${tmp_sql}"
    echoT "------------------------------------------------------------------"
    cat "${tmp_sql}" | tee -a "${f_log}"

    echoT "Exécution et journalisation"
    echoT "${SQLPLUS} -L -S / as sysdba @${tmp_sql} | tee -a ${f_log}"
    ${SQLPLUS} -L -S / as sysdba @"${tmp_sql}" 2>&1 | tee -a "${f_log}"
    local rc=${PIPESTATUS[0]}

    # Nettoyage du script temporaire
    rm -f -- "${tmp_sql}"

    #analyse_rslt "create_user_safirh_dest" ${rc} 0
    return ${rc}
}

function drop_schemas_to_import_utils_and_users() {
    # --- Validation préalable: aucune session connectée sur les utilisateurs/utilitaires visés ---
    local _targets=()

    if [[ -n "${MIGRATION_SCHEMAS:-}" ]]; then
        IFS=',' read -r -a __arrM <<< "${MIGRATION_SCHEMAS}"
        _targets+=("${__arrM[@]}")
    fi

    if [[ -n "${MIGR_SCHEMAS_UTIL:-}" ]]; then
        IFS=',' read -r -a __arrU <<< "${MIGR_SCHEMAS_UTIL}"
        _targets+=("${__arrU[@]}")
    fi

    if [[ -n "${dest_schema_name:-}" ]]; then
        _targets+=("${dest_schema_name}")
    fi

    if ((${#_targets[@]})); then
        declare -A __seen
        local __uniq=()
        local x
        for x in "${_targets[@]}"; do
            if [[ -n "$x" && -z "${__seen[$x]}" ]]; then
                __seen[$x]=1
                __uniq+=("$x")
            fi
        done
        wait_no_sessions_for_users "${__uniq[@]}" || return 1
    fi

    # Construit la liste (unique) des schémas à supprimer : utilisateurs + utilitaires
    local _all=""

    if [[ -n "${MIGRATION_SCHEMAS:-}" ]]; then
        _all="${MIGRATION_SCHEMAS}"
    fi

    if [[ -n "${MIGR_SCHEMAS_UTIL:-}" ]]; then
        local _util_list="${MIGR_SCHEMAS_UTIL}"

        # Si CTRL_LOG est présent et qu'on est en mode partiel (imp_ctrl_log_partiel=1),
        # on le retire de la liste
        if [[ ",${_util_list}," == *",CTRL_LOG,"* && "${imp_ctrl_log_partiel}" == "1" ]]; then
            _util_list=$(echo "${_util_list}" | sed 's/CTRL_LOG//g; s/,,/,/g; s/^,//; s/,$//')
        fi

        if [[ -n "${_util_list}" ]]; then
            if [[ -n "${_all}" ]]; then
                _all="${_all},${_util_list}"
            else
                _all="${_util_list}"
            fi
        fi
    fi
    
    # Rien à faire ?
    if [[ -z "${_all}" ]]; then
        echoT "Aucun schéma utilisateur/utilitaire à supprimer (MIGRATION_SCHEMAS/MIGR_SCHEMAS_UTIL vides)."
        return 0
    fi

    # Normalise : split, trim, uppercase, déduplication
    IFS=',' read -r -a _arr <<< "${_all}"
    declare -A _seen=()
    local _list=()
    local x t
    for x in "${_arr[@]}"; do
        t=$(echo "$x" | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')
        if [[ -z "$t" ]]; then
            continue
        fi
        t=$(echo "$t" | tr '[:lower:]' '[:upper:]')
        if [[ -n "${_seen[$t]:-}" ]]; then
            continue
        fi
        _seen[$t]=1
        _list+=("$t")
    done

    if ((${#_list[@]} == 0)); then
        echoT "Aucun schéma valide à supprimer."
        return 0
    fi

    echoT "***"
    echoT "Cible : CDB ${ORACLE_SID} / PDB ${ORACLE_PDB_SID}"
    echoT "Schémas potentiellement à supprimer : ${_list[*]}"
    echoT "***"

    local rc_all=0
    local ans
    local sch
    local exists
    local _out
    local rc

    for sch in "${_list[@]}"; do
        # 1) Vérifier si le schéma existe dans le PDB
        exists=$(${SQLPLUS} -L -S / as sysdba <<SQL
SET FEEDBACK OFF HEADING OFF PAGES 0 VERIFY OFF
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};
SELECT COUNT(*) FROM dba_users WHERE username = UPPER('${sch}');
EXIT;
SQL
)
        exists=$(echo "$exists" | tr -d '[:space:]')

        if [[ "$exists" == "0" ]]; then
            echoT "Schéma absent : ${sch}"
            continue
        elif [[ "$exists" != "1" ]]; then
            echoT "${YELLOW}ATTENTION${RESET} : impossible de déterminer l'existence du schéma ${sch} (valeur lue='${exists}')."
            # On continue tout de même
        fi

        # 2) Demander la confirmation uniquement si le schéma existe
        Question_YesNo "Voulez-vous vraiment supprimer le schéma ${BLUE}${sch}${RESET} sur le CDB ${BLUE}${ORACLE_SID}${RESET} et le PDB ${BLUE}${ORACLE_PDB_SID}${RESET} ? " ans
        if [[ "$ans" != "Y" ]]; then
            echoT "Suppression de ${sch} annulée par l'utilisateur."
            continue
        fi

        # 3) Drop dans le PDB (réel, avec CASCADE)
        _out=$(${SQLPLUS} -L -S / as sysdba <<SQL
set serveroutput on size 1000000
set feedback off heading off verify off pages 0 trimspool on
WHENEVER SQLERROR EXIT SQL.SQLCODE
alter session set container = ${ORACLE_PDB_SID};
DECLARE
  n NUMBER;
BEGIN
  SELECT COUNT(*) INTO n FROM dba_users WHERE username = UPPER('${sch}');
  IF n > 0 THEN
    EXECUTE IMMEDIATE 'DROP USER '||UPPER('${sch}')||' CASCADE';
    dbms_output.put_line('DROPPED:'||UPPER('${sch}'));
  ELSE
    dbms_output.put_line('MISSING:'||UPPER('${sch}'));
  END IF;
END;
/
exit
SQL
)
        rc=$?
        if [[ -n "$_out" ]]; then
            echoT "$_out"
        fi

        if (( rc != 0 )); then
            echoT "${RED}ERREUR${RESET} : échec du DROP USER ${sch} (rc=${rc})."
            rc_all=$rc
            # Si tu préfères arrêter au premier échec :
            # return $rc
        else
            echoT "${GREEN}OK${RESET} : suppression traitée pour ${sch}."
        fi
    done

    return $rc_all
}

# Fonction : create_roles
# But      : Récupérer sur la 11g les rôles qui ont des privilèges
#            sur les objets du schéma ${schema_name}.
#            puis créer localement (PDB 19c) les rôles manquants.
# Entrées  : schema_name, db_user, db_user_pwd, alias_db_src, ORACLE_PDB_SID
# Sorties  : Variable globale ROLES_FROM_SOURCE (CSV)
# Log      : Utilise echoT et ${f_log}
# ------------------------------------------------------------------
function create_roles() {
    if [[ -z "${schema_name:-}" ]]; then
        echoT "**************"
        echoT "*** ${RED}ERREUR${RESET} *** schema_name n'est pas défini."
        echoT "**************"
        return 1
    fi

    boite_titre "Détection des rôles (source 11g) qui on des grants sur ${schema_name}"

    # ----- 1) Récupère la liste des rôles depuis la 11g -----
    # On se base exactement sur le critère demandé, en le rendant robuste :
    # - Jointure dba_tab_privs -> dba_roles
    # - Filtre sur la table RREMPLOYE du propriétaire = schema_name
    # - OU bien rôle LIKE %TABLEAU%
    local _roles_raw
    _roles_raw=$(${SQLPLUS} -L -S "${db_user}/${db_user_pwd}@${alias_db_src}" <<SQL
set heading off feedback off pages 0 verify off echo off trimout on trimspool on
select distinct r.role
from   dba_tab_privs p
       inner join dba_roles r on r.role = p.grantee
where (p.owner = upper('${schema_name}') and p.table_name = 'RREMPLOYE')
   or r.role like '%TABLEAU%'
order  by r.role;
exit
SQL
)
    local _rc=$?
    if [[ ${_rc} -ne 0 ]]; then
        echoT "**************"
        echoT "*** ${RED}ERREUR${RESET} *** Connexion SQL*Plus (source 11g) échouée (rc=${_rc})."
        echoT "**************"
        return 1
    fi

    # Nettoyage
    _roles_raw=$(echo "${_roles_raw}" | sed '/^[[:space:]]*$/d')
    if [[ -z "${_roles_raw}" ]]; then
        echoT "${YELLOW}INFO${RESET} : Aucun rôle trouvé sur la 11g pour ${schema_name} (critères donnés)."
        ROLES_FROM_SOURCE=""
        return 0
    fi

    echoT "*** Rôles détectés sur la 11g :"
    echoT "${_roles_raw}"

    # Construit CSV et tableau
    ROLES_FROM_SOURCE=$(echo "${_roles_raw}" | paste -sd, -)
    IFS=',' read -r -a __ROLES_ARR <<< "${ROLES_FROM_SOURCE}"

    echoT "Rôles (CSV) : ${ROLES_FROM_SOURCE}"

    # ----- 2) Crée les rôles dans le PDB 19c s'ils n'existent pas -----
    boite_titre "Création des rôles manquants dans le PDB ${ORACLE_PDB_SID}"

    # Construit un bloc PL/SQL avec une collection des rôles
    local tmp_sql
    tmp_sql="$(mktemp /tmp/create_roles_${ORACLE_PDB_SID}_XXXX.sql)"

    {
        echo "set serveroutput on size 1000000"
        echo "set feedback off heading off verify off pages 0 trimspool on"
        echo "WHENEVER SQLERROR EXIT SQL.SQLCODE"
        echo "ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};"
        echo ""
        echo "DECLARE"
        echo "  TYPE t_list IS TABLE OF VARCHAR2(128);"
        echo "  l t_list := t_list("
        # Injecte les valeurs 'ROLE1','ROLE2',...
        local first=1
        while IFS= read -r r; do
            [[ -z "${r}" ]] && continue
            r=$(echo "${r}" | sed "s/'/''/g")   # échappe d'éventuels quotes
            if (( first )); then
                echo "    '${r}'"
                first=0
            else
                echo "   ,'${r}'"
            fi
        done <<< "${_roles_raw}"
        echo "  );"
        echo "  n number;"
        echo "BEGIN"
        echo "  FOR i IN 1..l.COUNT LOOP"
        echo "    SELECT COUNT(*) INTO n FROM dba_roles WHERE role = l(i);"
        echo "    IF n = 0 THEN"
        echo "      EXECUTE IMMEDIATE 'CREATE ROLE \"'||l(i)||'\"';"
        echo "      dbms_output.put_line('CREATED: '||l(i));"
        echo "    ELSE"
        echo "      dbms_output.put_line('EXISTS : '||l(i));"
        echo "    END IF;"
        echo "  END LOOP;"
        echo "END;"
        echo "/"
        echo "EXIT"
    } > "${tmp_sql}"

    echoT "Script de création des rôles : ${tmp_sql}"
    echoT "Exécution…"
    ${SQLPLUS} -L -S / as sysdba @"${tmp_sql}" 2>&1 | tee -a "${f_log}"
    local rc=${PIPESTATUS[0]}

    rm -f -- "${tmp_sql}"

    #analyse_rslt "create_roles" ${rc} 0
    return ${rc}
}

function import_related_and_users() {
    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "Import des schémas utilitaires et utilisateurs (sauf CTRL_LOG)"
    echoT "Dumpfile : ${f_dmp_users}"
    echoT "------------------------------------------------------------------"

    # Construire la liste brute
    local exp_schemas_list=""
    for v in "$MIGRATION_SCHEMAS" "$MIGR_SCHEMAS_UTIL" "$schema_name_childs"; do
        if [[ -n "$v" ]]; then
            if [[ -z "$exp_schemas_list" ]]; then
                exp_schemas_list="$v"
            else
                exp_schemas_list="$exp_schemas_list,$v"
            fi
        fi
    done

    # Normaliser : split, trim, uppercase, dédupliquer, retirer CTRL_LOG
    IFS=',' read -r -a _arr <<< "${exp_schemas_list}"
    declare -A _seen=()
    local _list=() x t
    for x in "${_arr[@]}"; do
        t=$(echo "$x" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        [[ -z "$t" ]] && continue
        t=$(echo "$t" | tr '[:lower:]' '[:upper:]')
        [[ "$t" == "CTRL_LOG" ]] && continue   # exclusion CTRL_LOG
        [[ -n "${_seen[$t]:-}" ]] && continue
        _seen[$t]=1
        _list+=("$t")
    done
    exp_schemas_list=$(IFS=,; echo "${_list[*]}")

    # Définir le logfile
    f_log_impdp_users="impdp_${f_dmp_users%.dmp}.log"

    # Options additionnelles
    local remap_opts=""
    if [[ "${dest_schema_name}" != "${schema_name}" && -n "${schema_name_childs_remap}" ]]; then
        remap_opts="${remap_opts} REMAP_SCHEMA=${schema_name_childs_remap},${schema_name_remap}"
    fi
    if [[ -n "${remap_tbs_dest_schema_name}" ]]; then
        remap_opts="${remap_opts} REMAP_TABLESPACE=${remap_tbs_dest_schema_name}"
    fi

    # Construire la commande impdp
    local cmd=( impdp "'/ as sysdba'" DIRECTORY=${directory_name} DUMPFILE=${f_dmp_users} LOGFILE=${f_log_impdp_users} SCHEMAS=${exp_schemas_list}${remap_opts} TRANSFORM=DISABLE_ARCHIVE_LOGGING:Y)

    echoT "Commande d'import à exécuter :"
    echoT "${cmd[*]}"

    # Exécution (désactivée pour l'instant)
    ${cmd[@]}
    rslt=$?
    #analyse_rslt "import_related_util_users_except_ctrl_log" ${rslt} 0
}

function import_metadata_safirh() {
    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "Import des métadonnées du schéma Safirh"
    echoT "Dumpfile : ${f_dmp_meta_safirh}"
    echoT "------------------------------------------------------------------"

    # Log d'impdp pour ce dump
    f_log_impdp_meta_safirh="impdp_${f_dmp_meta_safirh%.dmp}.log"

    # Options additionnelles
    local remap_opts=""
    if [[ "${dest_schema_name}" != "${schema_name}" && -n "${schema_name_remap}" ]]; then
        if [[ -z "${schema_name_childs_remap} ]]" ]]; then
            remap_opts+=" REMAP_SCHEMA=${schema_name_remap}"
        else
            remap_opts+=" REMAP_SCHEMA=${schema_name_remap},${schema_name_childs_remap}"
        fi
    fi
    if [[ -n "${remap_tbs_dest_schema_name}" ]]; then
        remap_opts+=" REMAP_TABLESPACE=${remap_tbs_dest_schema_name}"
    fi

    # Construire la commande impdp (connexion en '/ as sysdba')
    local cmd=( impdp "'/ as sysdba'" DIRECTORY=${directory_name} DUMPFILE=${f_dmp_meta_safirh} LOGFILE=${f_log_impdp_meta_safirh} CONTENT=METADATA_ONLY${remap_opts}  TRANSFORM=DISABLE_ARCHIVE_LOGGING:Y)

    echoT "Commande d'import à exécuter :"
    echoT "${cmd[*]}"

    # Exécution (désactivée pour l’instant)
    ${cmd[@]}
    rslt=$?
    #analyse_rslt "import_metadata_safirh" ${rslt} 0

    return 0
}

# Recrée dans CTRL_LOG les vues et triggers dont le nom contient ${schema_name}
# en remplaçant ${schema_name} par ${dest_schema_name} dans TOUT le DDL,
# puis supprime l'ancien objet.
function recreate_ctrl_log_objs_rename_segment() {

#####FONCTION NON UTILISÉE####
#####FONCTION NON UTILISÉE####
#####FONCTION NON UTILISÉE####
    local _rc=0
    local SRC="${schema_name:-}"
    local DST="${dest_schema_name:-}"
    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "Recréation des vues et triggers de CTRL_LOG qui contiennent le schéma ${schema_name}"
    echoT "------------------------------------------------------------------"


    if [[ -z "${SRC}" || -z "${DST}" ]]; then
        echoT "ERREUR: variables 'schema_name' et 'dest_schema_name' requises."
        return 1
    fi

    # Oracle normalise en UPPER si non quoté : on travaille en UPPER pour matcher les noms d'objets
    local SRCU DSTU
    SRCU="$(echo "${SRC}" | tr '[:lower:]' '[:upper:]')"
    DSTU="$(echo "${DST}" | tr '[:lower:]' '[:upper:]')"

    echoT "Recréation des objets CTRL_LOG contenant '${SRCU}' ? '${DSTU}' ..."
    local tmpdir
    tmpdir="$(mktemp -d "/tmp/ctrl_log_ddl_${SRCU}_XXXXXX")" || return 1

    # 1) Lister les objets cibles (VIEW, TRIGGER) dont le nom contient SRCU
    local objlist
    objlist="$(${SQLPLUS} -L -S "${db_user}/${db_user_pwd}@${alias_db_dest}" <<SQL
SET HEADING OFF FEEDBACK OFF PAGES 0 VERIFY OFF ECHO OFF TRIMSPOOL ON
SELECT object_type||'|'||object_name
  FROM dba_objects
 WHERE owner = 'CTRL_LOG'
   AND object_type IN ('VIEW','TRIGGER')
   AND object_name LIKE '%'||'${SRCU}'||'%'
 ORDER BY object_type, object_name;
SQL
)"
    if [[ -z "${objlist// }" ]]; then
        echoT "Aucun objet CTRL_LOG de type VIEW/TRIGGER ne contient '${SRCU}'. Rien à faire."
        rm -rf "${tmpdir}"
        return 0
    fi

    echoT "Objets détectés :"
    # Affiche chaque ligne proprement avec echoT (et pas un seul echoT du bloc)
    while IFS= read -r line; do
        [[ -z "${line// }" ]] && continue
        echoT "  - ${line}"
    done <<< "${objlist}"

    # 2) Pour chaque objet, extraire DDL, transformer et exécuter
    local line type name ddlfile newddlfile
    while IFS= read -r line; do
        [[ -z "${line// }" ]] && continue
        type="${line%%|*}"
        name="${line#*|}"

        ddlfile="${tmpdir}/${type}_${name}.sql"
        newddlfile="${tmpdir}/${type}_${name}_NEW.sql"

        echoT "Traitement ${type} CTRL_LOG.${name} ..."

        # 2.a) Extraire le DDL (avec terminator)
        ${SQLPLUS} -L -S "${db_user}/${db_user_pwd}@${alias_db_dest}" <<SQL > "${ddlfile}"
SET LONG 1000000 LONGCHUNKSIZE 32767 PAGES 0 LINES 32767 TRIMSPOOL ON TRIMOUT ON FEEDBACK OFF VERIFY OFF ECHO OFF
BEGIN
  DBMS_METADATA.SET_TRANSFORM_PARAM(DBMS_METADATA.SESSION_TRANSFORM,'SQLTERMINATOR',TRUE);
  DBMS_METADATA.SET_TRANSFORM_PARAM(DBMS_METADATA.SESSION_TRANSFORM,'SEGMENT_ATTRIBUTES',FALSE);
  DBMS_METADATA.SET_TRANSFORM_PARAM(DBMS_METADATA.SESSION_TRANSFORM,'STORAGE',FALSE);
  DBMS_METADATA.SET_TRANSFORM_PARAM(DBMS_METADATA.SESSION_TRANSFORM,'TABLESPACE',FALSE);
END;
/
-- Note : pour VIEW/TRIGGER, object_type tel quel convient.
SELECT DBMS_METADATA.GET_DDL('${type}', '${name}', 'CTRL_LOG') FROM dual;
SQL

        if [[ ! -s "${ddlfile}" ]]; then
            echoT "  [AVERTISSEMENT] DDL vide pour ${type} ${name} — ignoré."
            continue
        fi

        # 2.b) Remplacer la sous-chaîne SRCU -> DSTU PARTOUT dans le DDL (noms d'objet et corps)
        #     On agit en brut sur la séquence de caractères (quotée/non-quotée), conformément à la demande.
        #     NB: on ne touche PAS à CTRL_LOG (owner). On ne remplace que la sous-chaîne du nom.
        sed -E "s/${SRCU}/${DSTU}/g" "${ddlfile}" > "${newddlfile}"

        # 2.c) Exécuter le nouveau DDL (créera l'objet avec le nouveau nom)
        echoT "  Exécution du DDL renommé..."
        ${SQLPLUS} -L -S "${db_user}/${db_user_pwd}@${alias_db_dest}" <<SQL | sed 's/^/    /'
SET ECHO ON FEEDBACK ON
WHENEVER SQLERROR EXIT SQL.SQLCODE
@${newddlfile}
EXIT
SQL
        _rc=$?
        if [[ ${_rc} -ne 0 ]]; then
            echoT "  [ERREUR] Échec lors de la création de l'objet renommé pour ${type} ${name} (RC=${_rc})."
            echoT "           Fichiers conservés dans ${tmpdir}."
            continue
        fi

        # 2.d) Supprimer l'ancien objet
        echoT "  Suppression de l'ancien objet CTRL_LOG.${name} ..."
        ${SQLPLUS} -L -S "${db_user}/${db_user_pwd}@${alias_db_dest}" <<SQL | sed 's/^/    /'
SET ECHO ON FEEDBACK ON
WHENEVER SQLERROR CONTINUE
DROP ${type} "CTRL_LOG"."${name}";
EXIT
SQL
    done <<< "${objlist}"

    echoT "Terminé. DDL dans ${tmpdir}"
    return 0
}

# Réécrit un SQL généré par impdp :
#  - remplace ${schema_name} -> ${dest_schema_name} (références + noms)
#  - CREATE [FORCE] VIEW / CREATE TRIGGER -> CREATE OR REPLACE ...
#  - renomme les triggers: TRB_${schema_name}* -> TRB_${dest_schema_name}*
#  - nettoie REM/PROMPT/SET/WHENEVER
# Usage: remap_schema_name <input_sql> <output_sql>
# ------------------------------------------------------------------
function remap_schema_name() {
    local in_sql="$1"
    local out_sql="$2"

    if [[ -z "${in_sql:-}" || -z "${out_sql:-}" ]]; then
        echoT "${RED}ERREUR${RESET} : remap_schema_name <input_sql> <output_sql>"
        return 1
    fi
    if [[ -z "${schema_name:-}" || -z "${dest_schema_name:-}" ]]; then
        echoT "${RED}ERREUR${RESET} : schema_name ou dest_schema_name non défini."
        return 2
    fi
    if [[ ! -s "${in_sql}" ]]; then
        echoT "${RED}ERREUR${RESET} : fichier d'entrée introuvable ou vide: ${in_sql}"
        return 3
    fi

    # Fichiers temporaires (dans le même répertoire que out_sql si possible)
    local out_dir
    out_dir="$(dirname -- "${out_sql}")"
    mkdir -p "${out_dir}" 2>/dev/null

    local tmp1 tmp2 tmp3
    tmp1="$(mktemp "${out_dir}/$(basename "${out_sql}").tmp1.XXXX")" || return 4
    tmp2="$(mktemp "${out_dir}/$(basename "${out_sql}").tmp2.XXXX")" || { rm -f "${tmp1}"; return 4; }
    tmp3="$(mktemp "${out_dir}/$(basename "${out_sql}").tmp3.XXXX")" || { rm -f "${tmp1}" "${tmp2}"; return 4; }

    # 1) Nettoyage léger
    sed -E \
      -e 's/^[[:space:]]*REM .*$//g' \
      -e 's/^[[:space:]]*PROMPT .*$//g' \
      -e 's/^[[:space:]]*SET[[:space:]].*$//g' \
      -e 's/^[[:space:]]*WHENEVER[[:space:]].*$//g' \
      "${in_sql}" > "${tmp1}" || { rm -f "${tmp1}" "${tmp2}" "${tmp3}"; return 5; }

    # 2) Remplacement global du nom applicatif par le nom destination (références + noms)
    sed -E \
      -e "s/\"${schema_name}\"/\"${dest_schema_name}\"/g" \
      -e "s/\\b${schema_name}\\b/${dest_schema_name}/g" \
      -e "s/VI_${schema_name}/VI_${dest_schema_name}/g" \
      -e "s/TRB_${schema_name}/TRB_${dest_schema_name}/g" \
      "${tmp1}" > "${tmp2}" || { rm -f "${tmp1}" "${tmp2}" "${tmp3}"; return 5; }

    # 3) CREATE [FORCE] VIEW -> CREATE OR REPLACE [FORCE] VIEW
    sed -E \
      -e 's/^([[:space:]]*)CREATE[[:space:]]+(FORCE[[:space:]]+)?VIEW/\1CREATE OR REPLACE \2VIEW/I' \
      "${tmp2}" > "${tmp3}" || { rm -f "${tmp1}" "${tmp2}" "${tmp3}"; return 5; }

    # 4) CREATE TRIGGER -> CREATE OR REPLACE TRIGGER 
    sed -E \
      -e 's/^([[:space:]]*)CREATE[[:space:]]+TRIGGER/\1CREATE OR REPLACE TRIGGER/I' \
      "${tmp3}" > "${out_sql}" || { rm -f "${tmp1}" "${tmp2}" "${tmp3}"; return 5; }

    rm -f "${tmp1}" "${tmp2}" "${tmp3}"
    echoT "SQL généré (modifié) : ${out_sql}"
    return 0
}

#Import du schéma BIUQ seul à partir du même dump que import_related_util_users
function import_schema_biuq() {

    if [[ -z "${f_dmp_users:-}" ]]; then
        echoT "${RED}ERREUR${RESET} : f_dmp_users n'est pas défini (dump introuvable)."
        return 1
    fi

    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "Import du schéma BIUQ"
    echoT "Dumpfile source : ${f_dmp_users}"
    echoT "Directory IMPDP : ${directory_name:-IMP_DIR}"
    echoT "------------------------------------------------------------------"
    echoT " "

    local f_log_impdp_biuq="impdp_${f_dmp_users%.dmp}_BIUQ.log"
    
    # Extraire les schémas contenant BIUQ (en ignorant la casse)
    local biuq_schemas=$(echo "${MIGR_SCHEMAS_UTIL}" | tr ',' '\n' | grep -i 'BIUQ' | paste -sd, -)

    if [[ "${schema_name}" == "${dest_schema_name}" ]]; then

        # On n'exclut ni les vues, ni les triggers et ni les grants
        local cmd_full=( impdp \"'/ as sysdba'\"
                         "DIRECTORY=${directory_name}"
                         "DUMPFILE=${f_dmp_users}"
                         "LOGFILE=${f_log_impdp_biuq}"
                         "SCHEMAS=${biuq_schemas}"
                         "TRANSFORM=DISABLE_ARCHIVE_LOGGING:Y")
    else
        # On exclut les grant car si le schéma de destination est différent, ça génère des erreurs alors on les refait après
        local cmd_full=( impdp \"'/ as sysdba'\"
                         "DIRECTORY=${directory_name}"
                         "DUMPFILE=${f_dmp_users}"
                         "LOGFILE=${f_log_impdp_biuq}"
                         "EXCLUDE=VIEW"
                         "EXCLUDE=TRIGGER"
                         "EXCLUDE=GRANT"
                         "SCHEMAS=${biuq_schemas}"
                         "TRANSFORM=DISABLE_ARCHIVE_LOGGING:Y")
    fi
        
    echoT "Commande d'import à exécuter (initial) :"
    printf -v _shown '%q ' "${cmd_full[@]}"; echoT "${_shown}"

    "${cmd_full[@]}"; local rslt=$?
    #echoT "***"
    #echoT "*** Les 2 erreurs ORA-39082 sur GET_WAITED_TIME et CHK_ERROR_LOG sont normales (grants manquants)!"
    #echoT "***"

    #analyse_rslt "import_schema_biuq" "${rslt}" 0

    if [[ ! "${schema_name}" == "${dest_schema_name}" ]]; then
        # --- MODE PARTIEL: extraire le DDL via SQLFILE, réécrire, exécuter ---


        mkdir -p "${d_tmp}" 2>/dev/null
        
        # sqlfile_raw n'a pas de path pour être utilisé par impdp
        local sqlfile_raw="biuq_extract_${schema_name}_raw.sql"
        local sqlfile_mod="${d_tmp}/biuq_extract_${schema_name}_mod.sql"

        # 1) Génère le SQL (DDL uniquement) pour VIEWS/TRIGGERS dont le nom contient ${schema_name}
        local cmd=( impdp \"'/ as sysdba'\"
                    "DIRECTORY=${directory_name}"
                    "DUMPFILE=${f_dmp_users}"
                    "LOGFILE=${f_log_impdp_biuq}"
                    "SCHEMAS=${biuq_schemas}"
                    "CONTENT=METADATA_ONLY"
                    "INCLUDE=VIEW"
                    "INCLUDE=TRIGGER"
                    "INCLUDE=GRANT"
                    "SQLFILE=${sqlfile_raw}" )
                    
        # On ajoute le path au nom du fichier généré par impdp (répertoire du DIRECTORY)
        sqlfile_raw="${imp_dp_dir}/biuq_extract_${schema_name}_raw.sql"
        
        echoT "Extraction DDL avec impdp SQLFILE…"
        printf -v _shown '%q ' "${cmd[@]}"; echoT "${_shown}"
        "${cmd[@]}"; local rc=$?
        #analyse_rslt "import_schema_biuq (SQLFILE)" "${rc}" 0
        if (( rc != 0 )); then
            return "${rc}"
        fi

        # 2) Réécriture via la fonction remap_schema_name
        remap_schema_name "${sqlfile_raw}" "${sqlfile_mod}"
        rc=$?
        #analyse_rslt "import_schema_biuq (remap_schema_name)" "${rc}" 0
        if (( rc != 0 )); then
            return "${rc}"
        fi

        # 3) Exécute le SQL modifié dans le PDB cible
        echoT "Application du DDL modifié dans le PDB ${ORACLE_PDB_SID}..."
        ${SQLPLUS} -L -S / as sysdba <<SQL 2>&1 | tee -a "${f_log}"
SET ECHO ON FEEDBACK ON VERIFY OFF PAGES 0 TRIMSPOOL ON
WHENEVER SQLERROR EXIT SQL.SQLCODE
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};
@"${sqlfile_mod}"
EXIT;
SQL
        rc=${PIPESTATUS[0]}
        #analyse_rslt "import_schema_biuq (apply SQL)" "${rc}" 0
    fi
}

#Import du schéma TABLEAU seul à partir du même dump que import_related_util_users
function import_schema_tableau() {

    if [[ -z "${f_dmp_users:-}" ]]; then
        echoT "${RED}ERREUR${RESET} : f_dmp_users n'est pas défini (dump introuvable)."
        return 1
    fi

    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "Import du schéma TABLEAU"
    echoT "Dumpfile source : ${f_dmp_users}"
    echoT "Directory IMPDP : ${directory_name:-IMP_DIR}"
    echoT "------------------------------------------------------------------"
    echoT " "

    local f_log_impdp_tableau="impdp_${f_dmp_users%.dmp}_TABLEAU.log"

    # Extraire les schémas contenant BIUQ (en ignorant la casse)
    local tableau_schemas=$(echo "${MIGR_SCHEMAS_UTIL}" | tr ',' '\n' | grep -i 'TAB' | paste -sd, -)

    if [[ "${schema_name}" == "${dest_schema_name}" ]]; then

        # On n'exclut ni les vues, ni les triggers et ni les grants
        local cmd_full=( impdp \"'/ as sysdba'\"
                         "DIRECTORY=${directory_name}"
                         "DUMPFILE=${f_dmp_users}"
                         "LOGFILE=${f_log_impdp_tableau}"
                         "SCHEMAS=${tableau_schemas}" 
                         "TRANSFORM=DISABLE_ARCHIVE_LOGGING:Y")
    else
        # On exclut les grant car si le schéma de destination est différent, ça génère des erreurs alors on les refait après
        local cmd_full=( impdp \"'/ as sysdba'\"
                         "DIRECTORY=${directory_name}"
                         "DUMPFILE=${f_dmp_users}"
                         "LOGFILE=${f_log_impdp_tableau}"
                         "EXCLUDE=VIEW"
                         "EXCLUDE=TRIGGER"
                         "EXCLUDE=GRANT"
                         "SCHEMAS=${tableau_schemas}"
                         "TRANSFORM=DISABLE_ARCHIVE_LOGGING:Y" )
    fi
        
    echoT "Commande d'import à exécuter (initial) :"
    printf -v _shown '%q ' "${cmd_full[@]}"; echoT "${_shown}"

    "${cmd_full[@]}"; local rslt=$?
    #echoT "***"
    #echoT "*** Les 2 erreurs ORA-39082 sur GET_WAITED_TIME et CHK_ERROR_LOG sont normales (grants manquants)!"
    #echoT "***"

    #analyse_rslt "import_schema_tableau" "${rslt}" 0


    if [[ ! "${schema_name}" == "${dest_schema_name}" ]]; then
        # --- MODE PARTIEL: extraire le DDL via SQLFILE, réécrire, exécuter ---

        mkdir -p "${d_tmp}" 2>/dev/null
        
        # sqlfile_raw n'a pas de path pour être utilisé par impdp
        local sqlfile_raw="tableau_extract_${schema_name}_raw.sql"
        local sqlfile_mod="${d_tmp}/tableau_extract_${schema_name}_mod.sql"

        # 1) Génère le SQL (DDL uniquement) pour VIEWS/TRIGGERS dont le nom contient ${schema_name}
        local cmd=( impdp \"'/ as sysdba'\"
                    "DIRECTORY=${directory_name}"
                    "DUMPFILE=${f_dmp_users}"
                    "LOGFILE=${f_log_impdp_tableau}"
                    "SCHEMAS=${tableau_schemas}"
                    "CONTENT=METADATA_ONLY"
                    "INCLUDE=VIEW"
                    "INCLUDE=TRIGGER"
                    "INCLUDE=GRANT"
                    "SQLFILE=${sqlfile_raw}" )
                    
        # On ajoute le path au nom du fichier généré par impdp (répertoire du DIRECTORY)
        sqlfile_raw="${imp_dp_dir}/tableau_extract_${schema_name}_raw.sql"
        
        echoT "Extraction DDL avec impdp SQLFILE…"
        printf -v _shown '%q ' "${cmd[@]}"; echoT "${_shown}"
        "${cmd[@]}"; local rc=$?
        #analyse_rslt "import_schema_tableau (SQLFILE)" "${rc}" 0
        if (( rc != 0 )); then
            return "${rc}"
        fi

        # 2) Réécriture via la fonction remap_schema_name
        remap_schema_name "${sqlfile_raw}" "${sqlfile_mod}"
        rc=$?
        #analyse_rslt "import_schema_tableau (remap_schema_name)" "${rc}" 0
        if (( rc != 0 )); then
            return "${rc}"
        fi

        # 3) Exécute le SQL modifié dans le PDB cible
        echoT "Application du DDL modifié dans le PDB ${ORACLE_PDB_SID}..."
        ${SQLPLUS} -L -S / as sysdba <<SQL 2>&1 | tee -a "${f_log}"
SET ECHO ON FEEDBACK ON VERIFY OFF PAGES 0 TRIMSPOOL ON
WHENEVER SQLERROR EXIT SQL.SQLCODE
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};
@"${sqlfile_mod}"
EXIT;
SQL
        rc=${PIPESTATUS[0]}
        #analyse_rslt "import_schema_tableau (apply SQL)" "${rc}" 0
    fi
}

#Import du schéma CTRL_LOG seul à partir du même dump que import_related_util_users_except_ctrl_log
function import_schema_ctrl_log() {

    if [[ -z "${f_dmp_users:-}" ]]; then
        echoT "${RED}ERREUR${RESET} : f_dmp_users n'est pas défini (dump introuvable)."
        return 1
    fi

    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "Import du schéma CTRL_LOG"
    echoT "Dumpfile source : ${f_dmp_users}"
    echoT "Directory IMPDP : ${directory_name:-IMP_DIR}"
    echoT "Mode            : $([[ "${imp_ctrl_log_partiel:-}" == "1" ]] && echo "partiel (vues+triggers liés à ${schema_name})" || echo 'initial (complet)')"
    echoT "------------------------------------------------------------------"

    local f_log_impdp_ctrl_log="impdp_${f_dmp_users%.dmp}_CTRL_LOG.log"

    if [[ "${imp_ctrl_log_partiel:-}" == "0" ]]; then

        # --- MODE INITIAL (complet) ---
        if [[ "${schema_name}" == "${dest_schema_name}" ]]; then
            # On n'exclut ni les vues, ni les triggers et ni les grants
            local cmd_full=( impdp \"'/ as sysdba'\"
                             "DIRECTORY=${directory_name}"
                             "DUMPFILE=${f_dmp_users}"
                             "LOGFILE=${f_log_impdp_ctrl_log}"
                             "SCHEMAS=CTRL_LOG" 
                             "TRANSFORM=DISABLE_ARCHIVE_LOGGING:Y" )
        else
            # On exclut les grant car si le schéma de destination est différent, ça génère des erreurs alors on les refait après
            local cmd_full=( impdp \"'/ as sysdba'\"
                             "DIRECTORY=${directory_name}"
                             "DUMPFILE=${f_dmp_users}"
                             "LOGFILE=${f_log_impdp_ctrl_log}"
                             "EXCLUDE=VIEW:\"LIKE '%${schema_name}%'\""
                             "EXCLUDE=TRIGGER:\"LIKE '%${schema_name}%'\""
                             "EXCLUDE=GRANT"
                             "SCHEMAS=CTRL_LOG" 
                             "TRANSFORM=DISABLE_ARCHIVE_LOGGING:Y")
        fi
        
        echoT "Commande d'import à exécuter (initial) :"
        printf -v _shown '%q ' "${cmd_full[@]}"; echoT "${_shown}"

        "${cmd_full[@]}"; local rslt=$?
        echoT "***"
        echoT "*** Les 2 erreurs ORA-39082 sur GET_WAITED_TIME et CHK_ERROR_LOG sont normales (grants manquants)!"
        echoT "***"

        #analyse_rslt "import_schema_ctrl_log" "${rslt}" 0
    fi


    # Grants post-import (initial)
    echoT "Application des GRANTs post-import sur CTRL_LOG (mode initial)"
    ${SQLPLUS} -L -S / as sysdba <<SQL 2>&1 | tee -a ${f_log}
WHENEVER SQLERROR EXIT SQL.SQLCODE
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};
GRANT SELECT ON "${dest_schema_name}"."CPFOURNISSEUR"    TO "CTRL_LOG" WITH GRANT OPTION;
GRANT SELECT ON "${dest_schema_name}"."MCEMPLOYE"        TO "CTRL_LOG" WITH GRANT OPTION;
GRANT SELECT ON "${dest_schema_name}"."MCSUC_CPT_BANQUE" TO "CTRL_LOG" WITH GRANT OPTION;
GRANT SELECT ON "${dest_schema_name}"."RRDAA_COMPTE"     TO "CTRL_LOG" WITH GRANT OPTION;
GRANT SELECT ON "${dest_schema_name}"."RRDEM_ADHASS"     TO "CTRL_LOG" WITH GRANT OPTION;
GRANT SELECT ON "${dest_schema_name}"."RRDEM_FOLIO"      TO "CTRL_LOG" WITH GRANT OPTION;
GRANT SELECT ON "${dest_schema_name}"."RRDOSSIER_EMP"    TO "CTRL_LOG" WITH GRANT OPTION;
GRANT SELECT ON "${dest_schema_name}"."RREFO_DETAIL"     TO "CTRL_LOG" WITH GRANT OPTION;
GRANT SELECT ON "${dest_schema_name}"."RREMPLOYE"        TO "CTRL_LOG" WITH GRANT OPTION;
GRANT EXECUTE ON SYS.DBMS_LOCK      TO CTRL_LOG;
GRANT EXECUTE ON SYS.DBMS_SCHEDULER TO CTRL_LOG;
GRANT EXECUTE ON SYS.UTL_INADDR     TO CTRL_LOG;
GRANT EXECUTE ON SYS.UTL_SMTP       TO CTRL_LOG;
GRANT EXECUTE ON SYS.DBMS_CRYPTO    TO CTRL_LOG;
GRANT EXECUTE ON SYS.DBMS_MONITOR   TO CTRL_LOG;
GRANT EXECUTE ON SYS.UTL_MAIL       TO CTRL_LOG;
EXIT;
SQL
    local rslt_g=${PIPESTATUS[0]}
    #analyse_rslt "import_schema_ctrl_log (grants)" "${rslt_g}" 1


    if [[ "${schema_name}" == "${dest_schema_name}" ]]; then
        # --- MODE PARTIEL: extraire le DDL via SQLFILE, réécrire, exécuter ---


        mkdir -p "${d_tmp}" 2>/dev/null
        
        # sqlfile_raw n'a pas de path pour être utilisé par impdp
        local sqlfile_raw="ctrl_log_extract_${schema_name}_raw.sql"
        local sqlfile_mod="${d_tmp}/ctrl_log_extract_${schema_name}_mod.sql"

        # 1) Génère le SQL (DDL uniquement) pour VIEWS/TRIGGERS dont le nom contient ${schema_name}
        local cmd=( impdp \"'/ as sysdba'\"
                    "DIRECTORY=${directory_name}"
                    "DUMPFILE=${f_dmp_users}"
                    "LOGFILE=${f_log_impdp_ctrl_log}"
                    "SCHEMAS=CTRL_LOG"
                    "CONTENT=METADATA_ONLY"
                    "INCLUDE=VIEW:\"LIKE '%${schema_name}%'\""
                    "INCLUDE=TRIGGER:\"LIKE '%${schema_name}%'\""
                    "SQLFILE=${sqlfile_raw}" )
                    
        # On ajoute le path au nom du fichier généré par impdp (répertoire du DIRECTORY)
        sqlfile_raw="${imp_dp_dir}/ctrl_log_extract_${schema_name}_raw.sql"
        
        echoT "Extraction DDL (partiel) avec impdp SQLFILE…"
        printf -v _shown '%q ' "${cmd[@]}"; echoT "${_shown}"
        "${cmd[@]}"; local rc=$?
        #analyse_rslt "import_schema_ctrl_log (SQLFILE partiel)" "${rc}" 0
        if (( rc != 0 )); then
            return "${rc}"
        fi

        # 2) Réécriture via la fonction remap_schema_name
        remap_schema_name "${sqlfile_raw}" "${sqlfile_mod}"
        rc=$?
        #analyse_rslt "import_schema_ctrl_log (remap_schema_name)" "${rc}" 0
        if (( rc != 0 )); then
            return "${rc}"
        fi

        # 3) Exécute le SQL modifié dans le PDB cible
        echoT "Application du DDL modifié dans le PDB ${ORACLE_PDB_SID}..."
        ${SQLPLUS} -L -S / as sysdba <<SQL 2>&1 | tee -a "${f_log}"
SET ECHO ON FEEDBACK ON VERIFY OFF PAGES 0 TRIMSPOOL ON
WHENEVER SQLERROR EXIT SQL.SQLCODE
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};
@"${sqlfile_mod}"
EXIT;
SQL
        rc=${PIPESTATUS[0]}
        analyse_rslt "import_schema_ctrl_log (apply SQL partiel)" "${rc}" 0
        return ${rc}
    fi
}

#Préparation des objets requis pour les tâches de migration dans le schéma ${db_user19c}
function prepare_required_objects_in_db_user19c() {
    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "Préparation des objets requis dans ${BLUE}${db_user19c}${RESET} (PDB ${BLUE}${ORACLE_PDB_SID}${RESET})"
    echoT "Tablespace cible : ${tbs_dest_schema_name}"
    echoT "------------------------------------------------------------------"

    ${SQLPLUS} -L -S / as sysdba <<SQL 2>&1 | tee -a "${f_log}"
SET SERVEROUTPUT ON SIZE 1000000
SET FEEDBACK OFF HEADING OFF VERIFY OFF PAGES 0 TRIMSPOOL ON
WHENEVER SQLERROR EXIT SQL.SQLCODE

DECLARE
  v_exists NUMBER;

  PROCEDURE ensure_table_sql_execution_log IS
  BEGIN
    SELECT COUNT(*) INTO v_exists
      FROM dba_tables
     WHERE owner = UPPER('${db_user19c}')
       AND table_name = 'SQL_EXECUTION_LOG';
    IF v_exists = 0 THEN
      EXECUTE IMMEDIATE '
        CREATE TABLE ${db_user19c}.sql_execution_log (
            prog_id         NUMBER,
            log_id          NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
            executed_sql    VARCHAR2(4000),
            execution_time  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status          VARCHAR2(50),
            error_message   VARCHAR2(4000)
        ) TABLESPACE "${tbs_dest_schema_name}"';
      dbms_output.put_line('CREATED: ${db_user19c}.SQL_EXECUTION_LOG');
    ELSE
      dbms_output.put_line('EXISTS : ${db_user19c}.SQL_EXECUTION_LOG');
    END IF;
  END;

  PROCEDURE ensure_table_disabled_triggers IS
  BEGIN
    SELECT COUNT(*) INTO v_exists
      FROM dba_tables
     WHERE owner = UPPER('${db_user19c}')
       AND table_name = 'DISABLED_TRIGGERS';
    IF v_exists = 0 THEN
      EXECUTE IMMEDIATE '
        CREATE TABLE ${db_user19c}.disabled_triggers (
            id            NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
            owner         VARCHAR2(256 CHAR),
            trigger_name  VARCHAR2(256 CHAR),
            status        VARCHAR2(256 CHAR)
        ) TABLESPACE "${tbs_dest_schema_name}"';
      dbms_output.put_line('CREATED: ${db_user19c}.DISABLED_TRIGGERS');
    ELSE
      dbms_output.put_line('EXISTS : ${db_user19c}.DISABLED_TRIGGERS');
    END IF;
  END;

BEGIN
  ensure_table_sql_execution_log;
  ensure_table_disabled_triggers;
END;
/
EXIT
SQL

    rslt=${PIPESTATUS[0]}
    #analyse_rslt "prepare_required_objects_in_db_user19c" ${rslt} 0
    return ${rslt}
}

#Drop les indexes Oracle Text (du moins ceux qui ont réussi à être importés)
function drop_oracle_text_indexes() {
    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "Suppression des index Oracle Text dans ${BLUE}${dest_schema_name}${RESET} (PDB ${BLUE}${ORACLE_PDB_SID}${RESET})"
    echoT "------------------------------------------------------------------"

    local idx_list=(
        "GS_HPA_C03"
        "GS_HCH_C05"
        "RR_EPF_C03"
        "MC_RDC_C01"
        "GS_HON_C03"
    )

    # Un seul here-doc ; la boucle est injectée dans le BEGIN via $( ... )
    ${SQLPLUS} -L -S / as sysdba <<SQL 2>&1 | tee -a "${f_log}"
SET SERVEROUTPUT ON SIZE 1000000
SET FEEDBACK OFF HEADING OFF VERIFY OFF PAGES 0 TRIMSPOOL ON
WHENEVER SQLERROR EXIT SQL.SQLCODE

ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};

DECLARE
  v_owner   VARCHAR2(128) := UPPER('${dest_schema_name}');
  v_exists  NUMBER;

  PROCEDURE drop_if_exists(p_owner IN VARCHAR2, p_index IN VARCHAR2) IS
  BEGIN
    SELECT COUNT(*) INTO v_exists
      FROM dba_indexes
     WHERE owner = p_owner
       AND index_name = p_index;

    IF v_exists > 0 THEN
      EXECUTE IMMEDIATE 'DROP INDEX "'||p_owner||'"."'||p_index||'"';
      dbms_output.put_line('DROPPED : '||p_owner||'.'||p_index);
    ELSE
      dbms_output.put_line('WARNING : '||p_owner||'.'||p_index||' inexistant, rien à faire.');
    END IF;
  EXCEPTION
    WHEN OTHERS THEN
      dbms_output.put_line('ERREUR sur '||p_owner||'.'||p_index||' -> '||SQLERRM);
  END;
BEGIN
$( for idx in "${idx_list[@]}"; do
     printf "  drop_if_exists(v_owner, '%s');\n" "$(echo "$idx" | tr '[:lower:]' '[:upper:]')"
   done )
END;
/
EXIT
SQL
    rslt=${PIPESTATUS[0]}
    #analyse_rslt "drop_oracle_text_indexes" ${rslt} 0
    return ${rslt}
}

#Exécution du PL/SQL pour changer la définition des VARCHAR2 de BYTE en CHAR
function convert_varchar2_byte_to_char() {
    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "  Conversion des VARCHAR2 BYTE?CHAR dans le schéma ${BLUE}${dest_schema_name}${RESET}"
    echoT "------------------------------------------------------------------"

    ${SQLPLUS} -L -S / as sysdba <<SQL 2>&1 | tee -a "${f_log}"
SET SERVEROUTPUT ON
SET FEEDBACK OFF HEADING OFF VERIFY OFF PAGES 0 TRIMOUT ON TRIMSPOOL ON
WHENEVER SQLERROR EXIT SQL.SQLCODE

ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};

DECLARE
    v_sql           CLOB;
    v_error_message VARCHAR2(4000);
    v_prog_id       NUMBER;
    CURSOR sql_cursor IS
        SELECT 'ALTER TABLE ' || c.owner || '.' || c.table_name ||
               ' MODIFY "' || c.column_name || '" ' || c.data_type ||
               '(' || c.data_length || ' CHAR)' AS generated_sql
          FROM dba_tables t
          INNER JOIN dba_tab_columns c
            ON t.owner = c.owner AND t.table_name = c.table_name
         WHERE t.owner = '${dest_schema_name}'
           AND c.data_type IN ('VARCHAR2','CHAR')
           AND c.char_used = 'B';
BEGIN
    SELECT NVL(MAX(prog_id),0)+1 INTO v_prog_id FROM ${db_user19c}.sql_execution_log;
    FOR sql_rec IN sql_cursor LOOP
        BEGIN
            v_sql := sql_rec.generated_sql;
            EXECUTE IMMEDIATE v_sql;
            INSERT INTO ${db_user19c}.sql_execution_log (prog_id, executed_sql, status)
            VALUES (v_prog_id, v_sql, 'SUCCESS');
        EXCEPTION
            WHEN OTHERS THEN
                v_error_message := SQLERRM;
                INSERT INTO ${db_user19c}.sql_execution_log (prog_id, executed_sql, status, error_message)
                VALUES (v_prog_id, v_sql, 'ERROR', v_error_message);
        END;
    END LOOP;
    COMMIT;
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Unexpected error: ' || SQLERRM);
        ROLLBACK;
END;
/
EXIT
SQL
    
    rc=${PIPESTATUS[0]}
    #analyse_rslt "convert_varchar2_byte_to_char" ${rc} 0
    if (( rc != 0 )); then
        return ${rc}
    fi

    # Validation : vérifier qu’il n’y a aucune ligne en échec et au moins un succès dans le journal
    local success_count failure_count
    read -r success_count failure_count <<< "$(${SQLPLUS} -L -S / as sysdba <<SQL
SET FEEDBACK OFF HEADING OFF VERIFY OFF PAGES 0
SELECT COUNT(CASE WHEN status='SUCCESS' THEN 1 END),
       COUNT(CASE WHEN status!='SUCCESS' THEN 1 END)
FROM ${db_user19c}.sql_execution_log
WHERE prog_id = (SELECT MAX(prog_id) FROM ${db_user19c}.sql_execution_log);
EXIT;
SQL
)"
    if [[ -z "$success_count" || -z "$failure_count" ]]; then
        echoT "${RED}ERREUR${RESET} : impossible de lire le log d’exécution (aucun résultat)."
        fin
        return 1
    fi
    if (( failure_count != 0 || success_count <= 0 )); then
        echoT "${RED}ERREUR${RESET} : conversion BYTE?CHAR partiellement ou totalement échouée (succès=${success_count}, échecs=${failure_count})."
        ${SQLPLUS} -L -S / as sysdba <<SQL
SELECT *
  FROM ${db_user19c}.sql_execution_log
 WHERE prog_id = (SELECT MAX(prog_id) FROM ${db_user19c}.sql_execution_log)
   AND status!='SUCCESS';
EXIT;
SQL
        
        continue_execution "Souhaitez-vous continuer malgré tout?"
    else
        echoT "${GREEN}OK${RESET} : conversion BYTE?CHAR réussie pour ${success_count} colonne(s)."
    fi
    return 0
}

#Exécution de plsql_json_orig.sql en étant connecté avec ${dest_schema_name}
function run_plsql_json_as_dest_schema() {
    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "  Exécution de plsql_json.sql en proxy ${BLUE}${db_user19c}[${dest_schema_name}]${RESET}"
    echoT "  PDB          : ${ORACLE_PDB_SID}"
    echoT "  Script SQL   : ${d_sql}/plsql_json.sql"
    echoT "------------------------------------------------------------------"

    # Vérification de l’existence du script SQL
    local sql_file="${d_sql}/plsql_json.sql"
    if [[ ! -f "$sql_file" ]]; then
        echoT "${RED}ATTENTION${RESET} : Le fichier ${sql_file} est introuvable."
        read -p "Veuillez copier ce fichier à l’endroit indiqué puis appuyez sur Enter pour continuer..." _dummy
        if [[ ! -f "$sql_file" ]]; then
            echoT "${RED}ERREUR${RESET} : le fichier ${sql_file} n’existe toujours pas. Arrêt du script."
            fin
            return 1
        fi
    fi

    # Étape 1 : accorder CONNECT THROUGH à l'usager cible
    ${SQLPLUS} -L -S / as sysdba <<SQL 2>&1 | tee -a "${f_log}"
SET ECHO ON FEEDBACK ON VERIFY OFF HEADING OFF PAGES 0 TRIMSPOOL ON
ALTER USER ${dest_schema_name} GRANT CONNECT THROUGH ${db_user19c};
EXIT;
SQL

    rc1=${PIPESTATUS[0]}
    if (( rc1 != 0 )); then
        #analyse_rslt "run_plsql_json_as_dest_schema" ${rc1} 0
        return ${rc1}
    fi

    # Étape 2 : exécuter le script en proxy
    ${SQLPLUS} -L -S /nolog  <<SQL 2>&1 | tee -a "${f_log}"
CONNECT ${db_user19c}[${dest_schema_name}]/${db_user19c_pwd}@${ORACLE_PDB_SID}
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};
@"${sql_file}"
EXIT;
SQL
    
    rc2=${PIPESTATUS[0]}
    #analyse_rslt "run_plsql_json_as_dest_schema" ${rc2} 0
    return ${rc2}
}

#Désactivation des triggers de ${dest_schema_name}
function disable_triggers_dest() {
    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "  Désactivation des triggers du schéma ${BLUE}${dest_schema_name}${RESET} (et CTRL_LOG) dans le PDB ${BLUE}${ORACLE_PDB_SID}${RESET}"
    echoT "------------------------------------------------------------------"

    ${SQLPLUS} -L -S / as sysdba <<SQL 2>&1 | tee -a "${f_log}"
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};

-- Sauvegarder les triggers déjà désactivés
INSERT INTO ${db_user19c}.disabled_triggers (owner, trigger_name, status)
    SELECT owner, trigger_name, status
      FROM dba_triggers
     WHERE owner = '${dest_schema_name}'
       AND status != 'ENABLED';
COMMIT;

SET SERVEROUTPUT ON
DECLARE
    v_sql           CLOB;
    v_error_message VARCHAR2(4000);
    v_prog_id       NUMBER;
    CURSOR sql_cursor IS
        SELECT 'ALTER TRIGGER ' || t.owner || '.' || t.trigger_name || ' DISABLE' AS generated_sql
          FROM dba_triggers t
         WHERE (t.owner = '${dest_schema_name}' OR t.owner = 'CTRL_LOG')
           AND t.status = 'ENABLED';
BEGIN
    -- Obtenir un nouveau prog_id pour le journal
    SELECT NVL(MAX(prog_id),0)+1 INTO v_prog_id FROM ${db_user19c}.sql_execution_log;

    -- Désactiver chaque trigger et enregistrer le résultat
    FOR sql_rec IN sql_cursor LOOP
        BEGIN
            v_sql := sql_rec.generated_sql;
            EXECUTE IMMEDIATE v_sql;
            INSERT INTO ${db_user19c}.sql_execution_log (prog_id, executed_sql, status)
            VALUES (v_prog_id, v_sql, 'SUCCESS');
        EXCEPTION
            WHEN OTHERS THEN
                v_error_message := SQLERRM;
                INSERT INTO ${db_user19c}.sql_execution_log (prog_id, executed_sql, status, error_message)
                VALUES (v_prog_id, v_sql, 'ERROR', v_error_message);
        END;
    END LOOP;
    COMMIT;
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Unexpected error: ' || SQLERRM);
        ROLLBACK;
END;
/
EXIT
SQL
    
    rc=${PIPESTATUS[0]}
    #analyse_rslt "disable_triggers_dest" ${rc} 0
    return ${rc}
}

# Désactivation des clés étrangères (FOREIGN KEY) de ${dest_schema_name}
function disable_fk_dest() {
    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "  Désactivation des FKs du schéma ${BLUE}${dest_schema_name}${RESET}"
    echoT "  PDB          : ${ORACLE_PDB_SID}"
    echoT "------------------------------------------------------------------"

    ${SQLPLUS} -L -S / as sysdba <<SQL 2>&1 | tee -a "${f_log}"
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};
SET SERVEROUTPUT ON
WHENEVER SQLERROR EXIT SQL.SQLCODE

-- 0) S'assurer que la table de suivi existe AVANT de la référencer statiquement
DECLARE
    v_exists NUMBER;
BEGIN
    SELECT COUNT(*) INTO v_exists
      FROM dba_tables
     WHERE owner = UPPER('${db_user19c}')
       AND table_name = 'DISABLED_CONSTRAINTS';
    IF v_exists = 0 THEN
        EXECUTE IMMEDIATE '
          CREATE TABLE ${db_user19c}.disabled_constraints (
              id               NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
              owner            VARCHAR2(256 CHAR),
              constraint_name  VARCHAR2(256 CHAR),
              table_name       VARCHAR2(256 CHAR),
              constraint_type  VARCHAR2(1 CHAR),
              status           VARCHAR2(8 CHAR),
              deferrable       VARCHAR2(14 CHAR),
              deferred         VARCHAR2(9 CHAR),
              validated        VARCHAR2(13 CHAR)  -- VALIDATED / NOT VALIDATED
          )';
        DBMS_OUTPUT.PUT_LINE('CREATED: ${db_user19c}.DISABLED_CONSTRAINTS');
    ELSE
        DBMS_OUTPUT.PUT_LINE('EXISTS : ${db_user19c}.DISABLED_CONSTRAINTS');
    END IF;
END;
/
-- 1) Bloc principal : maintenant la table existe, on peut l'utiliser en SQL statique
DECLARE
    v_sql           VARCHAR2(4000);
    v_error_message VARCHAR2(4000);
    v_prog_id       NUMBER;

    -- (1) Déclaration du CURSOR AVANT la procédure locale (selon ton constat)
    CURSOR c_disable IS
        SELECT 'ALTER TABLE ' || c.owner || '."' || c.table_name ||
               '" DISABLE CONSTRAINT "' || c.constraint_name || '"' AS generated_sql
          FROM dba_constraints c
         WHERE c.owner = UPPER('${dest_schema_name}')
           AND c.constraint_type = 'R'
           AND c.status = 'ENABLED';

    -- (2) Procédure locale
    PROCEDURE log_sql(p_prog_id NUMBER, p_sql CLOB, p_status VARCHAR2, p_err VARCHAR2 DEFAULT NULL) IS
    BEGIN
        INSERT INTO ${db_user19c}.sql_execution_log (prog_id, executed_sql, status, error_message)
        VALUES (p_prog_id, p_sql, p_status, p_err);
    END log_sql;

BEGIN
    -- Sauvegarde des FKs déjà désactivées (avant notre passage)
    INSERT INTO ${db_user19c}.disabled_constraints
        (owner, constraint_name, table_name, constraint_type, status, deferrable, deferred, validated)
        SELECT owner, constraint_name, table_name, constraint_type, status, deferrable, deferred, validated
          FROM dba_constraints
         WHERE owner = UPPER('${dest_schema_name}')
           AND constraint_type = 'R'
           AND status != 'ENABLED';
    COMMIT;

    -- prog_id pour ce run
    SELECT NVL(MAX(prog_id),0)+1 INTO v_prog_id FROM ${db_user19c}.sql_execution_log;

    -- Désactiver les FKs actives
    FOR r IN c_disable LOOP
        BEGIN
            v_sql := r.generated_sql;
            EXECUTE IMMEDIATE v_sql;
            log_sql(v_prog_id, v_sql, 'SUCCESS', NULL);

            -- Enregistrer l'état post-désactivation (validated d'origine conservé via dba_constraints)
            INSERT INTO ${db_user19c}.disabled_constraints
                (owner, constraint_name, table_name, constraint_type, status, deferrable, deferred, validated)
            SELECT owner, constraint_name, table_name, constraint_type, 'DISABLED', deferrable, deferred, validated
              FROM dba_constraints
             WHERE owner = UPPER('${dest_schema_name}')
               AND constraint_type = 'R'
               AND ('ALTER TABLE ' || owner || '."' || table_name ||
                    '" DISABLE CONSTRAINT "' || constraint_name || '"') = v_sql;

        EXCEPTION
            WHEN OTHERS THEN
                v_error_message := SQLERRM;
                log_sql(v_prog_id, v_sql, 'ERROR', v_error_message);
        END;
    END LOOP;

    COMMIT;
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Unexpected error: ' || SQLERRM);
        ROLLBACK;
END;
/
EXIT
SQL

    rc=${PIPESTATUS[0]}
    #analyse_rslt "disable_fk_dest" ${rc} 0
    return ${rc}
}

#Import des données de ${schema_name} dans ${dest_schema_name}
function import_data_from_schema_to_dest() {
    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "  Import des données du schéma Safirh dans le schéma destination"
    echoT "  Dump file : ${f_dmp_data_safirh}"
    echoT "  PDB       : ${ORACLE_PDB_SID}"
    echoT "------------------------------------------------------------------"

    # Détermination du log d'import pour les données
    f_log_impdp_data_safirh="impdp_${f_dmp_data_safirh%.dmp}.log"

    # Préparer les options de remapping si nécessaire
    local remap_opts=""
    # Remap de schéma si le nom de destination diffère du nom source
    if [[ "${dest_schema_name}" != "${schema_name}" && -n "${schema_name_remap}" ]]; then
        remap_opts+=" REMAP_SCHEMA=${schema_name_remap}"
    fi
    # Remap de tablespace si spécifié
    if [[ -n "${remap_tbs_dest_schema_name}" ]]; then
        remap_opts+=" REMAP_TABLESPACE=${remap_tbs_dest_schema_name}"
    fi

    # Parfile spécifique pour l'import des données
    local parfile="${d_par}/impdp_data_safirh.par"

    # Construction de la commande impdp : import des données uniquement avec parfile et remap éventuel
    local cmd=( impdp "'/ as sysdba'" DIRECTORY=${directory_name} DUMPFILE=${f_dmp_data_safirh} LOGFILE=${f_log_impdp_data_safirh} CONTENT=DATA_ONLY PARFILE=${parfile}${remap_opts} )

    # Affichage de la commande pour information
    echoT "Commande d'import des données à exécuter :"
    echoT "${cmd[*]}"

    # Exécution (désactivée pour l’instant). Décommentez pour lancer l’import :
    ${cmd[@]}
    rslt=$?
    #analyse_rslt \"import_data_from_schema_to_dest\" ${rslt} 0
    return ${rc}
}

#Recompilation (utlrp.sql) et calcul des stats du dictionnaire
function recompile_and_gather_dict_stats() {
    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "  Recompilation des objets invalides et collecte des statistiques"
    echoT "  PDB        : ${ORACLE_PDB_SID}"
    echoT "------------------------------------------------------------------"

    echoT "Recompile les objets invalides avec utlrp"
    ${SQLPLUS} -L -S / as sysdba <<SQL 2>&1 | tee -a "${f_log}"
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};
@?/rdbms/admin/utlrp
EXIT;
SQL
    
    rc1=${PIPESTATUS[0]}
    #analyse_rslt "recompile_and_gather_dict_stats" ${rc1} 0
    if (( rc1 != 0 )); then
        return ${rc1}
    fi
    
    # On fait une 2ème passe car après la première il reste des objets invalides
    # qui sont en fait valides (sûrement l'ordre de recompilation qui fait ça)
    echoT "2ème recompilation des objets invalides avec utlrp"
    ${SQLPLUS} -L -S / as sysdba <<SQL 2>&1 | tee -a "${f_log}"
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};
@?/rdbms/admin/utlrp
EXIT;
SQL
    
    rc1=${PIPESTATUS[0]}
    #analyse_rslt "recompile_and_gather_dict_stats" ${rc1} 0
    if (( rc1 != 0 )); then
        return ${rc1}
    fi

    echoT "Validation – compter les objets restant invalides"
    local invalid_count
    invalid_count=$(${SQLPLUS} -L -S / as sysdba <<SQL
SET FEEDBACK OFF HEADING OFF VERIFY OFF PAGES 0
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};
SELECT COUNT(*) FROM dba_objects WHERE status != 'VALID';
EXIT;
SQL
    )
    invalid_count=$(echo "$invalid_count" | xargs)
    if [[ -n "$invalid_count" && "$invalid_count" -ne 0 ]]; then
        echoT "${YELLOW}AVERTISSEMENT${RESET} : Il reste ${invalid_count} objet(s) invalides après recompilation."
        echoT "Liste des objets invalides :"
        ${SQLPLUS} -L -S / as sysdba <<SQL 2>&1 | tee -a "${f_log}"
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};
SET FEEDBACK OFF VERIFY OFF PAGES 0 LINESIZE 180
SET HEADING ON
COLUMN owner       FORMAT A30 HEAD "OWNER"
COLUMN object_name FORMAT A80 HEAD "OBJECT_NAME"
COLUMN object_type FORMAT A30 HEAD "OBJECT_TYPE"
SELECT owner, object_name, object_type
  FROM dba_objects
 WHERE status != 'VALID'
 ORDER BY owner, object_name, object_type;
EXIT;
SQL
        
    fi

    echoT "Collecte des statistiques dictionnaire, objets fixes et base"
    ${SQLPLUS} -L -S / as sysdba <<SQL 2>&1 | tee -a "${f_log}"
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};
EXEC dbms_stats.gather_dictionary_stats;
EXEC dbms_stats.gather_fixed_objects_stats;
EXEC dbms_stats.gather_database_stats;
EXIT;
SQL
    
    rc2=${PIPESTATUS[0]}
    #analyse_rslt "recompile_and_gather_dict_stats" ${rc2} 0
    return ${rc2}
}

#Réactivation des triggers de ${dest_schema_name}
function enable_triggers_dest() {
    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "  Réactivation des triggers du schéma ${BLUE}${dest_schema_name}${RESET} (et CTRL_LOG)"
    echoT "  PDB          : ${ORACLE_PDB_SID}"
    echoT "------------------------------------------------------------------"

    ${SQLPLUS} -L -S / as sysdba <<SQL 2>&1 | tee -a "${f_log}"
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};
SET SERVEROUTPUT ON
DECLARE
    v_sql           CLOB;
    v_error_message VARCHAR2(4000);
    v_prog_id       NUMBER;
    CURSOR sql_cursor IS
        SELECT 'ALTER TRIGGER ' || t.owner || '.' || t.trigger_name || ' ENABLE' AS generated_sql
          FROM dba_triggers t
         WHERE (t.owner = '${dest_schema_name}' OR t.owner = 'CTRL_LOG')
           AND t.status = 'DISABLED'
           AND t.owner || '.' || t.trigger_name NOT IN
               (SELECT owner || '.' || trigger_name FROM ${db_user19c}.disabled_triggers);
BEGIN
    -- Obtenir un nouveau prog_id pour le journal
    SELECT NVL(MAX(prog_id), 0) + 1 INTO v_prog_id FROM ${db_user19c}.sql_execution_log;

    -- Boucle sur les triggers à réactiver
    FOR sql_rec IN sql_cursor LOOP
        BEGIN
            v_sql := sql_rec.generated_sql;
            EXECUTE IMMEDIATE v_sql;
            INSERT INTO ${db_user19c}.sql_execution_log (prog_id, executed_sql, status)
            VALUES (v_prog_id, v_sql, 'SUCCESS');
        EXCEPTION
            WHEN OTHERS THEN
                v_error_message := SQLERRM;
                INSERT INTO ${db_user19c}.sql_execution_log (prog_id, executed_sql, status, error_message)
                VALUES (v_prog_id, v_sql, 'ERROR', v_error_message);
                -- Poursuit malgré l’erreur
        END;
    END LOOP;
    COMMIT;
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Unexpected error: ' || SQLERRM);
        ROLLBACK;
END;
/
EXIT
SQL
    
    rc=${PIPESTATUS[0]}
    #analyse_rslt "enable_triggers_dest" ${rc} 0
    if (( rc != 0 )); then
        return ${rc}
    fi

    # Validation : vérifier qu’il n’y a aucune ligne en échec et au moins un succès dans le journal
    local success_count failure_count
    read -r success_count failure_count <<< "$(${SQLPLUS} -L -S / as sysdba <<SQL
SET FEEDBACK OFF HEADING OFF VERIFY OFF PAGES 0
SELECT COUNT(CASE WHEN status='SUCCESS' THEN 1 END),
       COUNT(CASE WHEN status!='SUCCESS' THEN 1 END)
FROM ${db_user19c}.sql_execution_log
WHERE prog_id = (SELECT MAX(prog_id) FROM ${db_user19c}.sql_execution_log);
EXIT;
SQL
)"
    if [[ -z "$success_count" || -z "$failure_count" ]]; then
        echoT "${RED}ERREUR${RESET} : impossible de lire le log d’exécution (aucun résultat)."
        fin
        return 1
    fi
    if (( failure_count != 0 || success_count <= 0 )); then
        echoT "${RED}ERREUR${RESET} : réactivation des triggers partiellement ou totalement échouée (succès=${success_count}, échecs=${failure_count})."
        fin
        return 1
    else
        echoT "${GREEN}OK${RESET} : réactivation des triggers réussie pour ${success_count} trigger(s)."
    fi
    return 0
}

# Réactivation des clés étrangères (FOREIGN KEY) de ${dest_schema_name}
function enable_fk_dest() {
    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "  Réactivation des FKs du schéma ${BLUE}${dest_schema_name}${RESET}"
    echoT "  PDB          : ${ORACLE_PDB_SID}"
    echoT "------------------------------------------------------------------"

    ${SQLPLUS} -L -S / as sysdba <<SQL 2>&1 | tee -a "${f_log}"
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};
SET SERVEROUTPUT ON
DECLARE
    v_sql            VARCHAR2(4000);
    v_error_message  VARCHAR2(4000);
    v_prog_id        NUMBER;

    /*
      Idée clé :
        - On NE réactive que les FKs que notre script a désactivées :
          on s'appuie sur ${db_user19c}.sql_execution_log (entrées '... DISABLE CONSTRAINT ...' en SUCCESS).
        - On RESTAURE l'état de validation :
            * DBA_CONSTRAINTS.VALIDATED = 'VALIDATED'     -> ENABLE VALIDATE
            * DBA_CONSTRAINTS.VALIDATED = 'NOT VALIDATED' -> ENABLE NOVALIDATE
        - Les FKs qui étaient déjà désactivées AVANT notre passage (pre-existantes)
          ne seront pas réactivées, car elles n'auront pas d'entrée correspondante
          'DISABLE CONSTRAINT' en SUCCESS dans le sql_execution_log.
    */

    CURSOR c_enable IS
        SELECT DISTINCT
            'ALTER TABLE ' || c.owner || '."' || c.table_name || '" ' ||
            CASE WHEN c.validated = 'VALIDATED'
                 THEN 'ENABLE VALIDATE '
                 ELSE 'ENABLE NOVALIDATE '
            END ||
            'CONSTRAINT "' || c.constraint_name || '"' AS generated_sql
        FROM dba_constraints c
        WHERE c.owner = UPPER('${dest_schema_name}')
          AND c.constraint_type = 'R'
          AND c.status = 'DISABLED'
          -- Cette FK a été désactivée par notre script (trace trouvée en SUCCESS)
          AND EXISTS (
                SELECT 1
                  FROM ${db_user19c}.sql_execution_log l
                 WHERE l.status = 'SUCCESS'
                   AND l.executed_sql = 'ALTER TABLE ' || c.owner || '."' || c.table_name
                                        || '" DISABLE CONSTRAINT "' || c.constraint_name || '"'
              );

BEGIN
    -- Nouveau prog_id pour journaliser cette réactivation
    SELECT NVL(MAX(prog_id), 0) + 1 INTO v_prog_id FROM ${db_user19c}.sql_execution_log;

    FOR r IN c_enable LOOP
        BEGIN
            v_sql := r.generated_sql;
            EXECUTE IMMEDIATE v_sql;

            INSERT INTO ${db_user19c}.sql_execution_log (prog_id, executed_sql, status)
            VALUES (v_prog_id, v_sql, 'SUCCESS');

        EXCEPTION
            WHEN OTHERS THEN
                v_error_message := SQLERRM;
                INSERT INTO ${db_user19c}.sql_execution_log (prog_id, executed_sql, status, error_message)
                VALUES (v_prog_id, v_sql, 'ERROR', v_error_message);
                -- Continuer malgré l'erreur
        END;
    END LOOP;
    COMMIT;

EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Unexpected error: ' || SQLERRM);
        ROLLBACK;
END;
/
EXIT
SQL

    rc=${PIPESTATUS[0]}
    #analyse_rslt "enable_fk_dest" ${rc} 0
    if (( rc != 0 )); then
        return ${rc}
    fi

    # Validation : s'assurer qu'il y a au moins un succès et aucun échec pour ce prog_id
    local success_count failure_count
    read -r success_count failure_count <<< "$(${SQLPLUS} -L -S / as sysdba <<SQL
SET FEEDBACK OFF HEADING OFF VERIFY OFF PAGES 0
SELECT COUNT(CASE WHEN status='SUCCESS' THEN 1 END),
       COUNT(CASE WHEN status!='SUCCESS' THEN 1 END)
FROM ${db_user19c}.sql_execution_log
WHERE prog_id = (SELECT MAX(prog_id) FROM ${db_user19c}.sql_execution_log);
EXIT;
SQL
)"
    if [[ -z "$success_count" || -z "$failure_count" ]]; then
        msg_status 1 "Impossible de lire le log d’exécution (aucun résultat)."
        fin
        return 1
    fi
    if (( failure_count != 0 || success_count <= 0 )); then
        msg_status 1 "Réactivation des FKs partiellement ou totalement échouée (succès=${success_count}, échecs=${failure_count})."
        fin
        return 1
    else
        msg_status 0 "Réactivation des FKs réussie pour ${success_count} contrainte(s)."
    fi
    return 0
}

#Création des index Oracle Text
function create_oracle_text_indexes() {
    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "  Création des index Oracle Text dans ${BLUE}${dest_schema_name}${RESET} à partir de la source 11g (${schema_name})"
    echoT "  Source : ${alias_db_src} (11g)  |  Cible : PDB ${ORACLE_PDB_SID} (19c)"
    echoT "------------------------------------------------------------------"
    
    local _rc_global=0
    
    # Préconditions
    if [[ -z "${schema_name:-}" || -z "${dest_schema_name:-}" ]]; then
        msg_status 1 "Schema_name et/ou dest_schema_name non défini(s)."
        return 1
    fi

    # 1) Récupérer la liste des index DOMAIN sur la source 11g
    local idx_list
    idx_list=$(${SQLPLUS} -L -S "${db_user}/${db_user_pwd}@${alias_db_src}" <<SQL
set heading off feedback off pages 0 verify off echo off trimout on trimspool on
select index_name
from   dba_indexes
where  owner = upper('${schema_name}')
  and  index_type = 'DOMAIN'
order  by index_name;
exit
SQL
)
    local rc=$?
    if (( rc != 0 )); then
        msg_status 1 "Échec de la connexion à la BD source pour lister les index (rc=${rc})."
        return ${rc}
    fi

    # Nettoyage sortie
    idx_list=$(echo "${idx_list}" | sed '/^[[:space:]]*$/d')
    if [[ -z "${idx_list}" ]]; then
        msg_status 2 "Aucun index Oracle Text (DOMAIN) trouvé sur la source (${schema_name})."
        return 0
    fi

    # Dossier temporaire pour scripts
    local tmpdir
    tmpdir="$(mktemp -d /tmp/ctxidx.XXXXXX)" || { echoT "${RED}ERREUR${RESET} : mktemp a échoué."; return 1; }

    echoT "***"
    echoT "*** Téléchargement et adaptation des scripts depuis la source 11g ? ${tmpdir}"
    echoT "***"

    # 2) Pour chaque index, générer le script via CTX_REPORT, adapter, puis exécuter sur 19c
    local idx src_sql dst_sql
    while IFS= read -r idx; do
        [[ -z "$idx" ]] && continue
        src_sql="${tmpdir}/${idx}_src.sql"
        dst_sql="${tmpdir}/${idx}_dest.sql"

        # 2a) Récupération du script de création (CLOB) depuis la source
        ${SQLPLUS} -L -S "${db_user}/${db_user_pwd}@${alias_db_src}" <<SQL > "${src_sql}"
set heading off feedback off pages 0 verify off echo off long 2000000 longchunksize 32767 lines 200 trimout on trimspool on
select ctx_report.create_index_script('${schema_name}.'||'${idx}') from dual;
exit
SQL
        rc=$?
        if (( $rc != 0 )) || [[ ! -s "${src_sql}" ]]; then
            msg_status 2 "Impossible de générer le script pour l'index ${idx} (rc=${rc}). On passe au suivant."
            _rc_global= 1
            continue
        fi

        # 2b) Remplacement du schéma source par le schéma destination dans le script
        # - remplace "SCHEMA_SOURCE" (avec guillemets) et la version non-quotée (mots isolés)
        # - précaution : variables protégées dans sed
        sed \
          -e "s/\"${schema_name}\"/\"${dest_schema_name}\"/g" \
          -e "s/\\b${schema_name}\\b/${dest_schema_name}/g" \
          -e "s/OWNER[[:space:]]\\+${schema_name}/OWNER ${dest_schema_name}/g" \
          "${src_sql}" > "${dst_sql}"

        # 2c) Exécution du script sur la 19c (dans le PDB cible, SCHÉMA courant = dest_schema_name)
        echoT "Création de l'index Oracle Text ${idx} dans ${dest_schema_name}…"
        ${SQLPLUS} -L -S /nolog <<SQL 2>&1 | tee -a "${f_log}"
--WHENEVER SQLERROR EXIT SQL.SQLCODE
CONNECT ${db_user19c}[${dest_schema_name}]/${db_user19c_pwd}@${ORACLE_PDB_SID}
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};
@${dst_sql}
EXIT;
SQL
        
        rc=${PIPESTATUS[0]}
        msg ${rc} "create_oracle_text_indexes (${idx})"
        # On continue même si un index échoue, le résumé figurera dans le log
    done <<< "${idx_list}"

    # Option de nettoyage : conserver pour debug si besoin
    # rm -rf -- "${tmpdir}" 2>/dev/null || true

    echoT "Traitement terminé. Les détails figurent dans ${f_log}."
    return ${_rc_global}
}

# Migration des Network ACLs 11g -> Host ACEs 19c
function migrate_network_acls_to_host_aces() {
    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "  Migration des Network ACLs 11g vers des Host ACEs 19c"
    echoT "  Source : ${alias_db_src} (11g)  |  Cible : PDB ${ORACLE_PDB_SID} (19c)"
    echoT "------------------------------------------------------------------"

    # Préconditions
    if [[ -z "${db_user:-}" || -z "${db_user_pwd:-}" || -z "${alias_db_src:-}" ]]; then
        msg_status 0 "db_user/db_user_pwd/alias_db_src doivent être définis (source 11g)."
        return 1
    fi

    # 1) Récupérer et agréger les ACLs de la source 11g
    local tmp_csv rc
    tmp_csv="$(mktemp /tmp/acl_11g_XXXX.csv)" || { echoT "${RED}ERREUR${RESET} : mktemp a échoué."; return 1; }

    ${SQLPLUS} -L -S "${db_user}/${db_user_pwd}@${alias_db_src}" <<'SQL' > "${tmp_csv}"
set pages 0 lines 32767 feedback off verify off heading off echo off trimout on trimspool on
-- host|lower_port|upper_port|principal|privs_csv
SELECT a.host
       ||'|'||NVL(TO_CHAR(a.lower_port),'')
       ||'|'||NVL(TO_CHAR(a.upper_port),'')
       ||'|'||p.principal
       ||'|'||LISTAGG(p.privilege, ',') WITHIN GROUP (ORDER BY p.privilege)
FROM   dba_network_acls a
JOIN   dba_network_acl_privileges p ON a.acl = p.acl
WHERE  UPPER(p.is_grant) = 'TRUE'
GROUP  BY a.host, a.lower_port, a.upper_port, p.principal
ORDER  BY a.host, a.lower_port, a.upper_port, p.principal;
exit
SQL
    rc=$?
    if (( rc != 0 )); then
        msg_status 1 "Échec de l'extraction des ACLs sur la source 11g (rc=${rc})."
        rm -f -- "${tmp_csv}" 2>/dev/null || true
        return ${rc}
    fi

    # Nettoie les lignes vides
    sed -i '/^[[:space:]]*$/d' "${tmp_csv}"
    if [[ ! -s "${tmp_csv}" ]]; then
        msg_status 2 "Aucune ACL réseau à migrer depuis la source."
        rm -f -- "${tmp_csv}" 2>/dev/null || true
        return 0
    fi

    echoT " "
    echoT "Nombre d'entrées ACL à traiter : $(wc -l < "${tmp_csv}")"
    echoT " "

    # 2) Pour chaque entrée, ajouter sur 19c les ACE manquants
    local line host lport uport principal privs
    local rc_all=0
    while IFS='|' read -r host lport uport principal privs; do
        # Normalisation / valeurs NULL
        host="$(echo -n "${host}" | xargs)"
        principal="$(echo -n "${principal}" | xargs)"
        privs="$(echo -n "${privs}" | xargs)"
        [[ -z "${lport}" ]] && lport="NULL" || lport="${lport}"
        [[ -z "${uport}" ]] && uport="NULL" || uport="${uport}"

        echoT "Traitement: host='${host}' ports=[${lport}-${uport}] principal='${principal}' privs='${privs}'"

        # Génère un bloc PL/SQL qui:
        #  - vérifie chaque privilège (connect/resolve) avec CHECK_PRIVILEGE
        #  - ajoute un ACE pour le privilège manquant (APPEND_HOST_ACE)
        ${SQLPLUS} -L -S / as sysdba <<SQL | tee -a "${f_log}"
SET SERVEROUTPUT ON SIZE 1000000
SET FEEDBACK OFF HEADING OFF VERIFY OFF PAGES 0 TRIMSPOOL ON
WHENEVER SQLERROR EXIT SQL.SQLCODE

ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};

DECLARE
  v_host        VARCHAR2(4000) := q'~${host}~';
  v_lower_port  PLS_INTEGER := ${lport};
  v_upper_port  PLS_INTEGER := ${uport};
  v_principal   VARCHAR2(128) := UPPER(q'~${principal}~');
  -- Parse la liste CSV des privilèges et traite chacun
  v_csv  VARCHAR2(4000) := q'~${privs}~';
  v_pos  PLS_INTEGER := 1;
  v_next PLS_INTEGER;
  v_item VARCHAR2(4000);

  PROCEDURE ensure_one_priv(p_priv IN VARCHAR2) IS
    v_cnt NUMBER;
  BEGIN
    -- 0) Si le principal n'existe pas (USER ou ROLE), on ignore
    SELECT COUNT(*)
      INTO v_cnt
      FROM (
        SELECT 1 FROM dba_users WHERE username = v_principal
        UNION ALL
        SELECT 1 FROM dba_roles WHERE role = v_principal
      );
    IF v_cnt = 0 THEN
      DBMS_OUTPUT.put_line(
        'SKIP   : principal inexistant -> '||v_principal||
        ' ; privilège '||UPPER(p_priv)||' @ '||v_host||
        ' ['||NVL(TO_CHAR(v_lower_port),'*')||'-'||NVL(TO_CHAR(v_upper_port),'*')||']');
      RETURN;
    END IF;

    -- 1) Existe déjà ?
    SELECT COUNT(*)
      INTO v_cnt
      FROM DBA_HOST_ACES
     WHERE HOST = v_host
       AND NVL(LOWER_PORT,-1) = NVL(v_lower_port,-1)
       AND NVL(UPPER_PORT,-1) = NVL(v_upper_port,-1)
       AND UPPER(PRINCIPAL)   = v_principal
       AND UPPER(PRIVILEGE)   = UPPER(p_priv)
       AND GRANT_TYPE         = 'GRANT';

    IF v_cnt > 0 THEN
      DBMS_OUTPUT.put_line(
        'EXISTS : '||v_principal||' -> '||UPPER(p_priv)||' @ '||v_host||
        ' ['||NVL(TO_CHAR(v_lower_port),'*')||'-'||NVL(TO_CHAR(v_upper_port),'*')||']');
      RETURN;
    END IF;

    -- 2) Ajout de l’ACE manquant
    DBMS_NETWORK_ACL_ADMIN.APPEND_HOST_ACE(
      host        => v_host,
      lower_port  => v_lower_port,
      upper_port  => v_upper_port,
      ace         => XS\$ACE_TYPE(
                       privilege_list => XS\$NAME_LIST(UPPER(p_priv)),
                       principal_name => v_principal,
                       principal_type => XS_ACL.PTYPE_DB));
    COMMIT;

    DBMS_OUTPUT.put_line(
      'ADDED  : '||v_principal||' -> '||UPPER(p_priv)||' @ '||v_host||
      ' ['||NVL(TO_CHAR(v_lower_port),'*')||'-'||NVL(TO_CHAR(v_upper_port),'*')||']');

  EXCEPTION
    WHEN OTHERS THEN
      -- Ignore explicitement ORA-46238 (principal inexistant) et continue
      IF SQLCODE = -46238 OR INSTR(SQLERRM, 'ORA-46238') > 0 THEN
        DBMS_OUTPUT.put_line(
          'IGNORED: ORA-46238 pour '||v_principal||' -> '||UPPER(p_priv)||' @ '||v_host||
          ' ['||NVL(TO_CHAR(v_lower_port),'*')||'-'||NVL(TO_CHAR(v_upper_port),'*')||']');
        RETURN;
      END IF;
      DBMS_OUTPUT.put_line(
        'ERROR  : '||v_principal||' -> '||UPPER(p_priv)||' @ '||v_host||
        ' ['||NVL(TO_CHAR(v_lower_port),'*')||'-'||NVL(TO_CHAR(v_upper_port),'*')||'] : '||SQLERRM);
      RAISE;
  END ensure_one_priv;

BEGIN
  LOOP
    v_next := INSTR(v_csv, ',', v_pos);
    IF v_next = 0 THEN
      v_item := TRIM(UPPER(SUBSTR(v_csv, v_pos)));
      IF v_item IS NOT NULL THEN
        ensure_one_priv(v_item);
      END IF;
      EXIT;
    ELSE
      v_item := TRIM(UPPER(SUBSTR(v_csv, v_pos, v_next - v_pos)));
      IF v_item IS NOT NULL THEN
        ensure_one_priv(v_item);
      END IF;
      v_pos := v_next + 1;
    END IF;
  END LOOP;
END;
/
EXIT
SQL
        rc=${PIPESTATUS[0]}
        if (( rc != 0 )); then
            msg_status 1 "Échec de création/vérification ACE pour host='${host}' principal='${principal}' (rc=${rc})."
            rc_all=$rc
            # on continue pour traiter les autres lignes, le résumé figure dans le log
        fi
    done < "${tmp_csv}"

    rm -f -- "${tmp_csv}" 2>/dev/null || true

    return ${rc_all}
}

# Création/validation du Workspace APEX pour ${dest_schema_name}
# - Workspace      : ${dest_schema_name}
# - Schéma primaire: ${dest_schema_name}
# Connexion : / as sysdba (dans le bon PDB)
# Effet : crée le workspace s'il n'existe pas et garantit le mapping du schéma
# ------------------------------------------------------------------
function create_apex_workspace() {

    echoT "PDB cible                         : ${BLUE}${ORACLE_PDB_SID}${RESET}"
    echoT "Nom du workspace APEX             : ${BLUE}${dest_schema_name}${RESET}"
    echoT "Schéma primaire du workspace      : ${BLUE}${dest_schema_name}${RESET}"

    # Garde-fous
    if [[ -z "${dest_schema_name:-}" || -z "${ORACLE_PDB_SID:-}" ]]; then
        msg_status 1 "dest_schema_name ou ORACLE_PDB_SID non défini."
        return 1
    fi

    local tmp_sql
    tmp_sql="$(mktemp /tmp/create_ws_${dest_schema_name}_XXXX.sql)"

    cat > "${tmp_sql}" <<SQL
set serveroutput on feedback on verify off heading off pages 0 trimspool on
WHENEVER SQLERROR EXIT SQL.SQLCODE

-- Se placer dans le bon PDB
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};

DECLARE
  v_ws_exists NUMBER := 0;
  v_ws_id     NUMBER;
  v_map_cnt   NUMBER := 0;
BEGIN
  -- Vérifier qu'APEX est bien installé dans ce PDB
  BEGIN
    DECLARE v_dummy NUMBER; BEGIN
      EXECUTE IMMEDIATE 'select 1 from apex_release' INTO v_dummy;
    END;
  EXCEPTION
    WHEN OTHERS THEN
      RAISE_APPLICATION_ERROR(-20000, 'APEX n''est pas installé dans le PDB ${ORACLE_PDB_SID} ou apex_release est inaccessible.');
  END;

  -- Workspace existe ?
  SELECT COUNT(*) INTO v_ws_exists
    FROM apex_workspaces
   WHERE UPPER(workspace) = UPPER(q'[${dest_schema_name}]');

  IF v_ws_exists = 0 THEN
    -- Créer le workspace (schéma primaire = ${dest_schema_name})
    APEX_INSTANCE_ADMIN.ADD_WORKSPACE(
      p_workspace          => q'[${dest_schema_name}]',
      p_primary_schema     => q'[${dest_schema_name}]',
      p_additional_schemas => NULL);
    dbms_output.put_line('Workspace créé : ${dest_schema_name}');
  ELSE
    dbms_output.put_line('Workspace déjà présent : ${dest_schema_name}');
  END IF;

  -- S'assurer du mapping du schéma primaire vers le workspace
  SELECT workspace_id
    INTO v_ws_id
    FROM apex_workspaces
   WHERE UPPER(workspace) = UPPER(q'[${dest_schema_name}]');

  SELECT COUNT(*) INTO v_map_cnt
    FROM apex_workspace_schemas
   WHERE workspace_id = v_ws_id
     AND UPPER(schema) = UPPER(q'[${dest_schema_name}]');

  IF v_map_cnt = 0 THEN
    -- Ajouter le schéma si non mappé (idempotent)
    APEX_INSTANCE_ADMIN.ADD_SCHEMA(
      p_workspace => q'[${dest_schema_name}]',
      p_schema    => q'[${dest_schema_name}]');
    dbms_output.put_line('Mapping ajouté : ${dest_schema_name} -> workspace ${dest_schema_name}');
  ELSE
    dbms_output.put_line('Mapping déjà présent : ${dest_schema_name} -> workspace ${dest_schema_name}');
  END IF;
END;
/
EXIT
SQL

    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "Création/Validation du workspace ${BLUE}${dest_schema_name}${RESET} dans PDB ${BLUE}${ORACLE_PDB_SID}${RESET}"
    echoT "Script: ${tmp_sql}"
    echoT "------------------------------------------------------------------"
    cat "${tmp_sql}" | tee -a "${f_log}"

    echoT " "
    echoT "Exécution et journalisation"
    echoT " "
    echoT "${SQLPLUS} -L -S / as sysdba @${tmp_sql} | tee -a ${f_log}"
    ${SQLPLUS} -L -S / as sysdba @"${tmp_sql}" 2>&1 | tee -a "${f_log}"
    local rc=${PIPESTATUS[0]}

    # Nettoyage du script temporaire
    rm -f -- "${tmp_sql}"

    return ${rc}
}


function restore_parameters_tables() {

    # Sauvegarde des tables de paramètres du schéma ${dest_schema_name}

    {
        ${SQLPLUS} -L -S "/ as sysdba" \
            @"${d_sql}/restore_parametres.sql" "${dest_schema_name}" \
            | tee -a "${f_log}"
    } 2>&1
    rc=${PIPESTATUS[0]}
    
    return ${rc}
}

# ------------------------------------------------------------------
# Fonction : sync_gspas_val_cli_forms_title
# But      : Récupérer sur la 11g la valeur du paramètre
#            'Envir - Forms titre' dans ${schema_name}.GSPAS_VAL_CLI
#            et mettre à jour uniquement la date-heure (après
#            "en date du ") dans la même propriété de
#            ${dest_schema_name}.GSPAS_VAL_CLI (PDB 19c).
# Entrées  : schema_name, dest_schema_name, db_user, db_user_pwd,
#            alias_db_src, ORACLE_PDB_SID, SQLPLUS
# Sorties  : aucune (log via echoT / f_log)
# ------------------------------------------------------------------
function sync_gspas_val_cli_forms_title() {

    if [[ -z "${schema_name:-}" || -z "${dest_schema_name:-}" ]]; then
        msg_status 1 "Schema_name et/ou dest_schema_name n'est pas défini."
        return 1
    fi
    if [[ -z "${ORACLE_PDB_SID:-}" ]]; then
        msg_status 1 "ORACLE_PDB_SID n'est pas défini."
        return 1
    fi

    boite_titre "Synchronisation du paramètre 'Envir - Forms titre' (GSPAS_VAL_CLI)"

    # ----- 1) Lecture de la valeur sur la 11g -----
    echoT "*** Lecture du paramètre sur la BD source 11g (${schema_name}.GSPAS_VAL_CLI)"

    local _row _rc
    _row=$(${SQLPLUS} -L -S "${db_user}/${db_user_pwd}@${alias_db_src}" <<SQL
set heading off feedback off pages 0 verify off echo off trimout on trimspool on
select val.pascleint || ';' || val.pavval
from   ${schema_name}.gspas_val_cli val
       inner join ${schema_name}.gsparam_systeme pas
               on pas.pascleint = val.pascleint
where  pas.pasdsc = 'Envir - Forms titre';
exit
SQL
)
    _rc=$?
    if [[ ${_rc} -ne 0 ]]; then
        msg_status 1 "Connexion SQL*Plus (source 11g) échouée (rc=${_rc})."
        return 1
    fi

    # Nettoyage des lignes vides
    _row=$(echo "${_row}" | sed '/^[[:space:]]*$/d')

    local _nb_lines
    _nb_lines=$(echo "${_row}" | wc -l | awk '{print $1}')

    if [[ "${_nb_lines}" -eq 0 ]]; then
        msg_status 1 "Aucun paramètre 'Envir - Forms titre' trouvé sur la source 11g."
        return 1
    elif [[ "${_nb_lines}" -gt 1 ]]; then
        msg_status 1 "Plusieurs lignes trouvées pour 'Envir - Forms titre' sur la 11g (cas non géré) :"
        echoT "${_row}"
        return 1
    fi

    # Extraction PASCLEINT / PAVVAL
    local src_pascleint src_pavval src_datetime src_datetime_escaped
    local _line
    _line=$(echo "${_row}" | head -n1)

    src_pascleint=${_line%%;*}
    src_pavval=${_line#*;}

    # Trim espaces sur la clé
    src_pascleint=$(echo "${src_pascleint}" | tr -d '[:space:]')

    echoT "*** Paramètre lu sur la 11g:"
    echoT "      PASCLEINT = ${src_pascleint}"
    echoT "      PAVVAL    = ${src_pavval}"

    # ----- 1b) Extraction de la date-heure après "en date du " -----
    local date_marker="en date du "
    if [[ "${src_pavval}" != *"${date_marker}"* ]]; then
        msg_status 1 "La valeur source ne contient pas le marqueur \"${date_marker}\"."
        return 1
    fi

    # Récupère tout ce qui suit "en date du "
    src_datetime=${src_pavval#*"${date_marker}"}
    # Trim espaces éventuels en début
    src_datetime=$(echo "${src_datetime}" | sed 's/^[[:space:]]*//')

    echoT "*** Date-heure extraite depuis la 11g:"
    echoT "      DATETIME = ${src_datetime}"

    # Protection des quotes simples dans la date-heure
    src_datetime_escaped=$(echo "${src_datetime}" | sed "s/'/''/g")

    # ----- 2) Mise à jour dans la PDB 19c -----
    echoT "*** Mise à jour de ${dest_schema_name}.GSPAS_VAL_CLI dans le PDB ${ORACLE_PDB_SID} (remplacement de la date-heure)"

    local _sql_out rc
    _sql_out=$(${SQLPLUS} -L -S / as sysdba <<SQL
SET SERVEROUTPUT ON SIZE 1000000
SET FEEDBACK OFF HEADING OFF VERIFY OFF PAGES 0 TRIMSPOOL ON

WHENEVER SQLERROR EXIT SQL.SQLCODE

ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};

DECLARE
    v_cnt NUMBER;
BEGIN
    SELECT COUNT(*)
      INTO v_cnt
      FROM ${dest_schema_name}.gspas_val_cli
     WHERE pascleint = ${src_pascleint};

    IF v_cnt = 0 THEN
        dbms_output.put_line('WARNING: aucune ligne trouvée dans ${dest_schema_name}.GSPAS_VAL_CLI pour PASCLEINT=${src_pascleint}. Aucune mise à jour.');
    ELSE
        UPDATE ${dest_schema_name}.gspas_val_cli
           SET pavval = REGEXP_REPLACE(
                            pavval,
                            '(en date du )[0-9]{2}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}',
                            '\\1${src_datetime_escaped}'
                        )
         WHERE pascleint = ${src_pascleint};

        dbms_output.put_line('UPDATED: ' || SQL%ROWCOUNT || ' ligne(s) mise(s) à jour dans ${dest_schema_name}.GSPAS_VAL_CLI pour PASCLEINT=${src_pascleint}.');
    END IF;

    COMMIT;
END;
/
EXIT
SQL
)
    rc=$?

    # Affiche la sortie PL/SQL dans le log
    if [[ -n "${_sql_out}" ]]; then
        echoT "${_sql_out}"
    fi

    return ${rc}
}

# Fonction : update_forms_title_property
# But      : Récupérer la valeur PAVVAL de la propriété 'Envir - Forms titre'
#            depuis la 11g et la mettre à jour dans la PDB 19c.
# Entrées  : schema_name, dest_schema_name, db_user, db_user_pwd, 
#            alias_db_src, ORACLE_PDB_SID
# Sorties  : Mise à jour de GSPAS_VAL_CLI.PAVVAL
# Log      : Utilise echoT et ${f_log}
# ------------------------------------------------------------------
function update_forms_title_property() {

    boite_titre "Récupération de la propriété 'Envir - Forms titre' (source 11g)"

    # ----- 1) Récupère PASCLEINT et PAVVAL depuis la 11g -----
    local _property_data
    _property_data=$(${SQLPLUS} -L -S "${db_user}/${db_user_pwd}@${alias_db_src}" <<SQL
set heading off feedback off pages 0 verify off echo off trimout on trimspool on colsep '|'
select val.PASCLEINT, val.PAVVAL
from   ${schema_name}.GSPAS_VAL_CLI val
       inner join ${schema_name}.GSPARAM_SYSTEME pas 
       on pas.PASCLEINT = val.PASCLEINT
where  pas.PASDSC = 'Envir - Forms titre';
exit
SQL
)
    
    local _rc=$?
    #echo "DEBUG:_property_data:${_property_data}"
    if [[ ${_rc} -ne 0 ]]; then
        msg_status 1 "Connexion SQL*Plus (source 11g) échouée (rc=${_rc})."
        echoT "**************"
        return 1
    fi

    # Nettoyage
    _property_data=$(echo "${_property_data}" | sed '/^[[:space:]]*$/d')
    if [[ -z "${_property_data}" ]]; then
        echoT "${YELLOW}INFO${RESET} : Aucune valeur trouvée pour la propriété 'Envir - Forms titre' sur la 11g."
        return 0
    fi

    # Parse PASCLEINT|PAVVAL
    local _pascleint _pavval
    _pascleint=$(echo "${_property_data}" | cut -d'|' -f1 | xargs)
    _pavval=$(echo "${_property_data}" | cut -d'|' -f2 | xargs)

    echoT "*** Valeur trouvée :"
    echoT "    PASCLEINT = ${_pascleint}"
    echoT "    PAVVAL    = ${_pavval}"

    # ----- 2) Mise à jour dans le PDB 19c -----
    boite_titre "Mise à jour dans ${dest_schema_name}.GSPAS_VAL_CLI (PDB ${ORACLE_PDB_SID})"

    local tmp_sql
    tmp_sql="$(mktemp /tmp/update_forms_title_${ORACLE_PDB_SID}_XXXX.sql)"

    # Échappe les single quotes pour SQL
    local _pavval_escaped
    _pavval_escaped=$(echo "${_pavval}" | sed "s/'/''/g")

    {
        echo "set serveroutput on size 1000000"
        echo "set feedback on heading off verify off pages 0 trimspool on"
        echo "WHENEVER SQLERROR EXIT SQL.SQLCODE"
        echo "ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};"
        echo ""
        echo "UPDATE ${dest_schema_name}.GSPAS_VAL_CLI"
        echo "SET    PAVVAL = '${_pavval_escaped}'"
        echo "WHERE  PASCLEINT = ${_pascleint};"
        echo ""
        echo "COMMIT;"
        echo ""
        echo "BEGIN"
        echo "  IF SQL%ROWCOUNT = 0 THEN"
        echo "    dbms_output.put_line('ATTENTION: Aucune ligne mise à jour (PASCLEINT=${_pascleint} introuvable)');"
        echo "  ELSE"
        echo "    dbms_output.put_line('Mise à jour effectuée: '||SQL%ROWCOUNT||' ligne(s)');"
        echo "  END IF;"
        echo "END;"
        echo "/"
        echo "EXIT"
    } > "${tmp_sql}"

    echoT "Script de mise à jour : ${tmp_sql}"
    echoT "Exécution…"
    ${SQLPLUS} -L -S / as sysdba @"${tmp_sql}" 2>&1 | tee -a "${f_log}"
    local rc=${PIPESTATUS[0]}

    rm -f -- "${tmp_sql}"

    return ${rc}
}

# Retrait du rôle DBA à l'usager Safirh ${dest_schema_name}
function revoke_dba_safirh() {
    if [[ -z "${dest_schema_name:-}" ]]; then
        msg_status 1 "dest_schema_name n'est pas défini."
        return 1
    fi

    local tmp_sql
    tmp_sql="$(mktemp /tmp/revoke_dba_${dest_schema_name}_XXXX.sql)"

    cat > "${tmp_sql}" <<SQL
set echo on feedback on verify off heading off pages 0 trimspool on
WHENEVER SQLERROR EXIT SQL.SQLCODE

-- On travaille dans le bon PDB
ALTER SESSION SET CONTAINER = ${ORACLE_PDB_SID};

-- Retrait du rôle DBA
REVOKE DBA FROM "${dest_schema_name}";

EXIT
SQL

    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "REVOKE DBA FROM ${BLUE}${dest_schema_name}${RESET} dans PDB ${BLUE}${ORACLE_PDB_SID}${RESET}"
    echoT "Script: ${tmp_sql}"
    echoT "------------------------------------------------------------------"

    echoT "Exécution et journalisation"
    echoT "${SQLPLUS} -L -S / as sysdba @${tmp_sql} | tee -a ${f_log}"
    ${SQLPLUS} -L -S / as sysdba @"${tmp_sql}" 2>&1 | tee -a "${f_log}"
    local rc=${PIPESTATUS[0]}

    # Nettoyage du script temporaire
    rm -f -- "${tmp_sql}"

    return ${rc}
}


function exec_sql_script(){
    # Vu que c'est une fonction interne, aucun parametre n'est valide
    # Mise a part le script SQL où on valide qu'il existe
    # Chemin du script sql
    local _f_sql=${1}
    # Parametre optionnel. Defaut: O valeur reconnues : O ou N
    local _logging=${2}
    # Parametres optionnel: parametre envoyes au script SQL
    local _param1=${3}
    local _param2=${4}
    local _param3=${5}

    echoT " "
    echoT "------------------------------------------------------------------"
    echoT "Script SQL a executer   : ${_f_sql}"
    echoT "Sortie vers log general : ${_logging}"
    echoT "Parametre 1             : ${_param1}"
    echoT "Parametre 2             : ${_param2}"
    echoT "Parametre 3             : ${_param3}"
    rslt=0
    if [ ! -z ${_f_sql} ]; then
        if [ -f ${_f_sql} ]; then
            #echo "${SQLPLUS} / as sysdba @${_f_sql} ${_param1} ${_param2} ${_param3} 2>&1 | tee -a ${f_log};"
            if [ "${_logging}" == "Y" ]; then
                # La sortie du script est envoyee vers le log general
                { ${SQLPLUS} -S / as sysdba @${_f_sql} ${_param1} ${_param2} ${_param3} 2>&1 | tee -a ${f_log}; } 2>&1
                rslt=${PIPESTATUS[0]}
            else
                # La sortie du script est envoyee seulement dans la sortie standard
                ${SQLPLUS} -S / as sysdba @${_f_sql} ${_param1} ${_param2} ${_param3}
                rslt=$?
            fi
        else
            echoT "Script SQL non existant"
            statut=6
            fin
        fi
    else
        echoT "Parametre du script SQL non fourni"
    fi
    
    return ${rslt}
  
}

function choix_dmp_remote() {
    # Fonction pour le choix du dump sur un host distant (ssh passwordless)
    # Host  : oracle@${host11g_nfs_dmp_prod}
    # Dossier : ${nfs_export_prod}
    #
    # Usage:
    #   choix_dmp_remote VAR_RESULT
    #   # ou sans var: choix_dmp_remote && echo "$V_FILE"

    local __resultvar="$1"

    local _remote_user="oracle"
    local _remote_host="${host11g_nfs_dmp_prod}"
    local _remote_dir="${nfs_export_prod}"

    # Récupérer la liste triée par date (ancien -> récent, comme ls -tr)
    local -a _files
    mapfile -t _files < <(
        ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
            "${_remote_user}@${_remote_host}" \
            "ls -1tr ${_remote_dir}/*.dmp 2>/dev/null"
    )

    local _count=${#_files[@]}

    if [[ ${_count} -eq 0 ]]; then
        echoT "Aucun fichier .dmp trouvé sur ${_remote_user}@${_remote_host}:${_remote_dir}."
        V_FILE='AucunDMP'
        return 1
    fi

    echoT "Liste des fichiers .dmp sur ${_remote_user}@${_remote_host}:${_remote_dir}"
    echoT "Sélectionnez un fichier .dmp en entrant son numéro:"

    # Tailles + largeur max (affichage aligné)
    local -a sizes
    local max_size_len=0
    local f size hsize

    for f in "${_files[@]}"; do
        size=$(
            ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
                "${_remote_user}@${_remote_host}" \
                "stat -c%s \"$f\" 2>/dev/null"
        )
        [[ -z "$size" ]] && size=0
        hsize=$(numfmt --to=iec --suffix=B "$size" 2>/dev/null || echo "${size}B")
        sizes+=("$hsize")
        (( ${#hsize} > max_size_len )) && max_size_len=${#hsize}
    done

    for i in "${!_files[@]}"; do
        printf "%-3s %${max_size_len}s  %s\n" \
            "$((i+1)))" \
            "${sizes[$i]}" \
            "$(basename "${_files[$i]}")" \
            | while IFS= read -r line; do echoT "$line"; done
    done

    local choice
    while true; do
        read -p "Entrez votre choix (1-${_count}): " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 && $choice -le ${_count} ]]; then
            V_FILE="$(basename "${_files[$((choice-1))]}")"
            break
        else
            echoT "Choix invalide. Choisir un chiffre entre 1 et ${_count}."
        fi
    done

    echoT " "
    echoT "***"
    echoT "*** Fichier choisi: ${_remote_user}@${_remote_host}:${_remote_dir}/${V_FILE}"
    echoT "***"
    echoT " "

    # Retourne la valeur
    if [[ -n "${__resultvar}" ]]; then
        eval ${__resultvar}="'$V_FILE'"
    else
        echo "${V_FILE}"
    fi
}

function choix_dmp() {
    # Fonction pour le choix du dump 
    local __path="$1"
    local __resultvar="$2"
    
    local _files=($(ls -tr ${__path}/*.dmp 2>/dev/null))
    local _count=${#_files[@]}
    
    if [[ ${_count} -eq 0 ]]; then
        echoT "Aucun fichier .dmp trouvé dans ${__path}."
        V_FILE='AucunDMP'
        return 1
    fi

    echoT "Liste des fichiers .dmp dans le répertoire ${__path}"
    echoT "Sélectionnez un fichier .dmp en entrant son numéro:"

    # Récupérer tailles et déterminer la largeur max
    local -a sizes
    local max_size_len=0
    for f in "${_files[@]}"; do
        local size=$(stat -c%s "$f")
        local hsize=$(numfmt --to=iec --suffix=B "$size")
        sizes+=("$hsize")
        (( ${#hsize} > max_size_len )) && max_size_len=${#hsize}
    done

    # Affichage aligné
    for i in "${!_files[@]}"; do
        printf "%-3s %${max_size_len}s  %s\n" \
            "$((i+1)))" \
            "${sizes[$i]}" \
            "$(basename "${_files[$i]}")" \
            | while IFS= read -r line; do echoT "$line"; done
    done

    while true; do
        read -p "Entrez votre choix (1-${_count}): " choice
        if [[ $choice -ge 1 && $choice -le ${_count} ]]; then
            V_FILE="$(basename "${_files[$((choice-1))]}")"
            break
        else
            echoT "Choix invalide. Choisir un chiffre entre 1 et ${_count}."
        fi
    done

    echoT " "
    echoT "***"
    echoT "*** Fichier choisi: ${__path}/${V_FILE}"
    echoT "***"
    echoT " "

    # Retourne la valeur
    if [[ -n "${__resultvar}" ]]; then
        eval ${__resultvar}="'$V_FILE'"
    else
        echo "${V_FILE}"
    fi
}


####################################################################
####################################################################
####### Principal
####################################################################
####################################################################


    # retourne le chemin du script courant
    export dn=`dirname ${0}`
    export d_cmd=`(cd $dn; pwd)`
    export d_sql=${d_cmd}/sql
    export d_tmp=${d_cmd}/tmp
    export d_par=${d_cmd}/par
    export d_script=${d_cmd}/..
    export dthnosep=`date +%Y%m%d_%H%M%S`
    export d_log=${d_script}/log
    export f_log=${d_log}/migration_19c_${dthnosep}.log
    export f_mailconf=${d_script}/conf/info_mail.conf
    SUCCES=0
    ECHEC=1
    statut=${SUCCES}
    
    # Codes ANSI pour les Couleurs principales
    BLACK=$'\e[30m'
    RED=$'\e[31m'
    GREEN=$'\e[32m'
    YELLOW=$'\e[33m'
    BLUE=$'\e[34m'
    CLEARBLUE=$'\e[38;5;153m'
    MAGENTA=$'\e[35m'   # violet/rose
    CYAN=$'\e[36m'
    WHITE=$'\e[37m'

    # Styles utiles
    BOLD=$'\e[1m'
    UNDERLINE=$'\e[4m'
    RESET=$'\e[0m'
    
#    nb_steps=8
#    #Remplit la variable all_steps avec tous les numeros d'etapes separes par des virgules
#    for ((i=1; i<=nb_steps; i++)); do
#        if [ "$i" -ne 1 ]; then
#            all_steps="$all_steps,"
#        fi
#        all_steps="${all_steps}${i}"
#    done

    # Lecture des parametres de mail
    export mailfrom=`awk -F"=" '/^mailfrom/ { print $2 }' $f_mailconf`
    export mailto=`awk -F"=" '/^mailto/ { print $2 }' $f_mailconf`

    # Recuperation des parametres obligatoires: ORACLE_SID, ORACLE_PDB_SID
    #
    # Validation des parametres: 
    #
    if [ $# -lt 3 ] ; then
        echo "pas de parametre!"
        err_manque_parametre
    fi

    export ORACLE_SID=${1}
    export ORACLE_PDB_SID=${2}
    export ORAENV_ASK=NO
    . /usr/local/bin/oraenv
    
    alias_db_src=${3}
    
    SQLPLUS="${ORACLE_HOME}/bin/sqlplus"
    
    # nom des fichiers avec le ORACLE_SID
    export f_log_tmp=${d_log}/maj_prisme_tmp_${db_name}_${dthnosep}.log
    export f_log=${d_log}/migration_19c_${alias_db_src}_${dthnosep}.log
    #export f_log_var=${f_log}.var
    export f_conf=${d_script}/conf/info_cnx_bd_${ORACLE_SID}.conf
    
    # On Choisit le mode dans lequel le script doit être exécuté:
    #   - Migration simple d'un schéma 11g vers un schéma 19c
    #   - Rafraîchissement d'un env. de test 19c avec un le dernier dump d'une prod 11G    
    choix_mode_script
    
    # Valide si l'instance est disponible
    # Ajouter une validation qu'on n'est pas sur un serveur 11g. La procedure doit etre lancee depuis un serveur 19c
    check_instance
    
    # Utilisateur DBA et son mot de passe
    ask_dba_credentials
    #echo "db11g_name:${db11g_name}"

    valide_datapump_dir
    
    #Sélection des schéma à exporter/importer
    select_schema_app
    if [[ ${mode_script} -eq 1 ]]; then
        select_schema_util
        select_schema_user
        validation_tablespaces
        # Choix des dumps
        dmp_setup
    else
        # En mode copie+migration, le choix du dump se fait sur la prod 11g
        choix_dmp_prod_11g
    fi
    
    resume_travail

    # Sélection des étapes à exécuter
    select_steps
        
    echoT "*** Execution des etapes suivantes : ${selected_steps}"

    continue_execution "Souhaitez-vous commencer la migration?"
    
    # Exécute les étapes sélectionnées
    run_selected_steps
    
    fin

