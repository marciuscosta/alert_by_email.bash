#!/bin/bash
#
# Script que envia e-mail atraves do active-response do Wazuh
#
# Por Marcius em 02/11/2022

# Arquivo de log do active-response
LOG_AR=/var/ossec/logs/active-responses.log

# Verifica se o 'jq' esta instalado no SO
if [[ `which jq ; echo $? ` -ne 0 ]]; then
        echo "`date` - O 'jq' precisa estar instalado no sistema operacional. Script finalizado." >> $LOG_AR
        exit 1
fi

# Captura o alerta passado pelo Wazuh em formato json e salva na variavel ALERTA
read -r ALERTA

ACAO=`echo $ALERTA | jq '.command' | tr -d "\""`
EMAIL_FROM=`cat /etc/postfix/sasl_passwd | cut -d " " -f2 | cut -d ":" -f1`	# Endereço de e-mail que enviara os alertas
# Endereco(s) de email(s) que recebera(ao) os alertas enviados
EMAILS[0]=`echo $ALERTA | jq '.parameters.extra_args' | tr -d "\""`
#EMAILS[1]=exemplo@email.com
ALERT_ID=`echo $ALERTA | jq '.parameters.alert.id' | tr -d "\""`
TXTEMAIL=/tmp/alert_$ALERT_ID.email				# Arquivo temporario de preparacao para o email
IP=`echo $ALERTA | jq '.parameters.alert.data.srcip' | tr -d "\""`
AGENT_ID=`echo $ALERTA | jq '.parameters.alert.agent.id' | tr -d "\""`
AGENT_NAME=`echo $ALERTA | jq '.parameters.alert.agent.name' | tr -d "\""`
TIMESTAMP=`echo $ALERTA | jq '.parameters.alert.predecoder.timestamp' | tr -d "\""` # Dia e hora originais do log do evento
RULE_DESCRIPTION=`echo $ALERTA | jq '.parameters.alert.rule.description' | tr -d "\""`
RULE_ID=`echo $ALERTA | jq '.parameters.alert.rule.id' | tr -d "\""`

# Logando
echo "`date` $0 $ALERTA" >> $LOG_AR


# Coletando informacoes sobre o IP de origem
ip_info() {
	ORIGEM=`/usr/bin/curl -s http://ip-api.com/csv/$1 `
	IP_INFO_STATUS=`echo $ORIGEM | cut -d ',' -f1`
	if [[ $IP_INFO_STATUS != "success" ]]; then
		echo "$1 - IP privado"
	else
		echo $ORIGEM | awk -v ip="$IP" -F ',' '{print ip" - "$11" ("$5", "$6" - "$2")"}'
	fi
}

if [[ $ACAO == "add" ]]; then

	# Preparando email
	echo "From: WAZUH Relatorios <"$EMAIL_FROM">" > $TXTEMAIL
	echo "Date: "$(date '+%a, %d %b %Y %H:%M:%S -0300') >> $TXTEMAIL
	echo "Subject: Relatorio do alerta "$ALERT_ID >> $TXTEMAIL
	echo "Mime-Version: 1.0" >> $TXTEMAIL
	echo "Content-Type: text/html; charset='UTF-8'" >> $TXTEMAIL
	echo "" >> $TXTEMAIL
	echo "" >> $TXTEMAIL
	echo "" >> $TXTEMAIL
	echo "<div style='font-family:arial; font-size:32px; height:50px; margin-top:20px;'><center><b>Relat&oacute;rio do alerta "$ALERT_ID"</b></center></div>" >> $TXTEMAIL

	# Info sobre o alerta
	echo "<table style='height: 33px; border-color: #AAAAAA; font-family:arial; border-style: solid; border-width:1px;' width='100%'><tbody><tr style='background-color:#B40404; color:#FFFFFF; text-align:center; height:30px;'><td colspan='2'><b>Informa&ccedil;&otilde;es sobre o alerta</b></td></tr>" >> $TXTEMAIL
	echo "<p><b>IP do atacante: </b>" ` ip_info $IP ` "<p>" >> $TXTEMAIL
	echo "<p><b>Alvo: </b>"$AGENT_ID" - "$AGENT_NAME"<p>" >> $TXTEMAIL
	echo "<p><b>Ocorrido em: </b>"$TIMESTAMP"<p>" >> $TXTEMAIL
	echo "<p><b>Regra usada: </b>"$RULE_ID" - "$RULE_DESCRIPTION"<p>" >> $TXTEMAIL
	echo "</tbody></table>" >> $TXTEMAIL

	# Alerta do Wazuh no seu estado original
	echo "<p></p>" >> $TXTEMAIL
	echo "<table style='height: 33px; border-color: #AAAAAA; font-family:arial; border-style: solid; border-width:1px;' width='100%'><tbody><tr style='background-color:#B40404; color:#FFFFFF; text-align:center; height:30px;'><td colspan='2'><b>Alerta original do Wazuh sobre esse alerta</b></td></tr>" >> $TXTEMAIL
	echo "<pre>" >> $TXTEMAIL
	echo $ALERTA | jq | sed -z 's/\n/<br>/g' >> $TXTEMAIL
	echo "</pre>" >> $TXTEMAIL
	echo "</tbody></table>" >> $TXTEMAIL

	# Envia o alerta por e-mail
        TOTALEMAILS=${#EMAILS[@]}
        A=`echo $(( $TOTALEMAILS -1 ))`
        while [[ $TOTALEMAILS -ge 1 ]]; do
		/usr/sbin/sendmail -r $EMAIL_FROM -t ${EMAILS[$A]} < $TXTEMAIL	# envia email
                (( A-- ))
                (( TOTALEMAILS-- ))
        done

	# Remove o arquivo temporario de e-mail
	rm -fr $TXTEMAIL

else
        echo "`date` $0 'Erro ao executar o script de envio de email de alerta - '$ALERTA" >> $LOG_AR
fi
