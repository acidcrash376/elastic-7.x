#!/bin/bash
# ------------------------------------------------------------------
# [Author     ] acidcrash376
# [Title      ] ELK (v7.x) stack install script
# [Description] Script to install Elasticearch, Logstash and Kibana
# [Created    ] 06/09/2020
# [Last Update] 08/06/2022
# [Version    ] v1.2
# [URL        ] https://github.com/acidcrash376/ELK-7.9-Install-Script
# ------------------------------------------------------------------

#######################
# Declarations        #
#######################
ip=$(hostname -I)
ip=`echo $ip | sed 's/ *$//g'`
elasticpath='/etc/elasticsearch/*'
kibanapath='/etc/kibana/*'
logstashpath='/etc/logstash/*'
nginxpath='/etc/nginx/*'
#######################
# Functions           #
#######################

function checkpriv {
if [ "$EUID" -ne 0 ]
        then
                echo -e "\e[31m        Please run as root! Exiting...\e[39m"
                exit
fi
}

function getreq {
dpkg -s $1 &> /dev/null
if [ $? -ne 0 ]
        then
        apt update &> /dev/null
        apt install $1 -y &> /dev/null
        echo -e "\e[32m [\xE2\x9C\x94]" $1 "has been installed\e[0m"
    else
        echo -e "\e[32m [\xE2\x9C\x94]"  $1 "is already installed\e[0m"
fi
}

function initialCheckSvc()
{
echo -e "\e[33m [-] Checking ${1} service is running\e[0m"
ps auxw | grep -v grep | grep -w $1 > /dev/null
if [ $? != 0 ]
then
        systemctl start elasticsearch.service;
        sleep 2
        checkSvc $1
else
        echo -e "\e[32m [\xE2\x9c\x94] "$1" is running";
fi;
}

function checkSvc()
{
ps auxw | grep -v grep | grep -w $1 > /dev/null
if [ $? != 0 ]
then
        systemctl start $1
        initialCheckSvc $1;
        sleep 1
else
        echo -e "\e[32m [\xE2\x9c\x94] "$1" is running";
fi;
}

function checkPort()
{
ip=$(hostname -I)
ip=`echo $ip | sed 's/ *$//g'`
echo -e "\e[33m [-] Checking ${2} is listening on port ${1}\e[0m"
vara=$(ss -tln | grep -v :: | grep :${1} | cut -d":" -f2 | cut -d" " -f1)
while ! ss -tln | grep [0-9]:${1} -q; do
        sleep 5
done
vara=$(ss -tln | grep -v :: | grep :${1} | cut -d":" -f2 | cut -d" " -f1)
echo -e "\e[32m [\xE2\x9c\x94] "$2 "is listening on "$vara "\e[0m";
}

function generate-cacert() {
cat <<"EOF" > /etc/logstash/certs/ca.crt
-----BEGIN CERTIFICATE-----
MIIDiTCCAnGgAwIBAgIUCoozmhp+PMdzwF4ZXJk4QYSnSXEwDQYJKoZIhvcNAQEL
BQAwVDELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDENMAsGA1UEAwwEc2llbTAeFw0yMjA1
MTcxMDI1MzZaFw0zMjA1MTQxMDI1MzZaMFQxCzAJBgNVBAYTAkFVMRMwEQYDVQQI
DApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQx
DTALBgNVBAMMBHNpZW0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4
MsCZP1e33PgE2UelQU5PNF7N4WH6aX0A/5ecAL8wAvKX24QPWIv9B1aJZpdaJToC
BHrshPqb/VxyGB+Z0kNLIOv/Ldc0WjHA8cWoQ59vnRSpj6kt5SaUMwVx+wjxcpE7
+hayEM7gHY34hgzPmmbPXeo3kW+DQ+olhXM16nh8x+vHMVK0S2liKhFNGEOQj8eA
4BaXapZL6nG4wJMl/Qxmo76MJUPJg3gZin7dzEd70qEbMJLANvK/R0lgjG4DjWl1
6Vv4PlO+Z/uzojFxIooSPQwTi0YCId1lPerFb37hP//FsCdJkVBZi0CecE+tEusH
An+whd2WAYe1aRf/BTfRAgMBAAGjUzBRMB0GA1UdDgQWBBRH29FQBbE4OvoMx/Ba
WSZlyfcoaTAfBgNVHSMEGDAWgBRH29FQBbE4OvoMx/BaWSZlyfcoaTAPBgNVHRMB
Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB57CJJfrLS1a3Ng1xpOPJ5h202
W25qwpPaBtzyx+5NWNiL83eAOqVzOBFnSBGKkZhvrrvbOwQN5W21BYaf5tVie+vF
RzSPZKcMyV3Zu2JgwAWichxDxuwDFWDTy1Af/Ehcbj/V4NjnKKwafMDxJgjP2Bpr
7P2XayiICx62q8qkWWSigbeLMQqqXUfqD0pNxPnywcuF7HOjqzbVjlk/F8lKlcEE
nw38irbspBLhKBeThB8N6p8hXjKTVZBxsM08tdsdK1VfUpckyQzQ0NYgqBW+dhBh
Xah9gQ4fs0ujtW6Yc0IFAIxqUoslofPATPeK127AHDTVPmeHflU6GeirJaUs
-----END CERTIFICATE-----
EOF
}

function generate-logstashcert() {
cat <<"EOF" > /etc/logstash/certs/logstash.crt
-----BEGIN CERTIFICATE-----
MIIDojCCAoqgAwIBAgIUCoozmhp+PMdzwF4ZXJk4QYSnSXIwDQYJKoZIhvcNAQEN
BQAwVDELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDENMAsGA1UEAwwEc2llbTAeFw0yMjA1
MTcxMDI2NTBaFw0zMjA1MTQxMDI2NTBaMIGKMQswCQYDVQQGEwJYWDEPMA0GA1UE
CAwGWFhYWFhYMQ8wDQYDVQQHDAZYWFhYWFgxDzANBgNVBBEMBlhYWFhYWDEPMA0G
A1UECgwGWFhYWFhYMQ8wDQYDVQQLDAZYWFhYWFgxDzANBgNVBAMMBlhYWFhYWDEV
MBMGCSqGSIb3DQEJARYGWFhYWFhYMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA49G7tvZxN0SwFoPWeF123xYxSJB8eRoSEeVDn1oNKdfrPfFylE3MqRSO
MbyTmylEA9lCI+vzhPXMRRsHsvSfdnhx6GUWYPO6JG/GXCC7LRiRvK2rWFbx1GEd
SlJrAcAEI5J6MQZzLwPmYyaHJT3BoKPW0EboFHGy0U16Kktlog8XlXmkyB7K097p
XScsV7iFTrdRpUvqowJyy1/fU+S9Ror7l0znT06RGfjSAqlrpi0SDD2112C6u9U5
FCgvl6Jl7aA/YdvqBFN1BQXO0qYs2RSIgI+y77gZ/hHf2fdacCWrkQsrG+q2CsG9
x5SiLG6tu0T1k+RSIysYtb/hVuIZFQIDAQABozUwMzALBgNVHQ8EBAMCBDAwEwYD
VR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0RBAgwBoIEc2llbTANBgkqhkiG9w0BAQ0F
AAOCAQEALKt13BBt7xMi+xYVP/KrzKWuPvmlSsZOyYwQ0WbTYNS6HWLs7bJZHNnw
g+T9vuIBLbt1Ix65sBSy9FKIHOI12hbP5Iu5mlK5lnVBDKRC8grAgHkr3f/ZQwNB
I57Wy5uQjctnDJdozbhGykaD/5ilmsLiVBnP+xGeKzN5DA8OQ4EStJjuBJPM0rlm
m4yLU5QjCDk8l82+2gpQgtadP7DF9rbCRXSKOQ5rYy/Zs1CQSqwq2CxX5tJXnV7z
1tM0Ve35d6Ceg7miawywotg5b6nQyljQ0hjx28AZPeyYVfcS1leWM0OxqAhP/wkO
3s9oe4ZO/agTFsEnz/qJUASWa8tI+Q==
-----END CERTIFICATE-----
EOF
}

function generate-logstashkey() {
cat <<"EOF" > /etc/logstash/certs/logstash.key
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDj0bu29nE3RLAW
g9Z4XXbfFjFIkHx5GhIR5UOfWg0p1+s98XKUTcypFI4xvJObKUQD2UIj6/OE9cxF
Gwey9J92eHHoZRZg87okb8ZcILstGJG8ratYVvHUYR1KUmsBwAQjknoxBnMvA+Zj
JoclPcGgo9bQRugUcbLRTXoqS2WiDxeVeaTIHsrT3uldJyxXuIVOt1GlS+qjAnLL
X99T5L1GivuXTOdPTpEZ+NICqWumLRIMPbXXYLq71TkUKC+XomXtoD9h2+oEU3UF
Bc7SpizZFIiAj7LvuBn+Ed/Z91pwJauRCysb6rYKwb3HlKIsbq27RPWT5FIjKxi1
v+FW4hkVAgMBAAECggEAQXMjxrCOXh5xqEY/+1x+piCuD/bSi8gdoN6IyuMIHRlX
D/ipvkmLnpe1MjzG+zCjxadJBSDoWS50fPYDBDqbBWIc93LzNu9ObuFdz2Hn5FDG
rboHG93+o9EypQOAkoQjrESMrkD4Hm20Zo/PC7fuRMRNFpEIY7c2dEMZ8cSvchrw
/b0kRpBMyIJOKShQyKMBeK9OvLb2Yj7dGmI18RKiPFyQ5F42CdYILJ7I65YP9usF
FKJ8KMVCKZ2s4YngQw04r5AbtajPOoD7DPv3QOF2B7E0Yx3glxWPGM8aRYqsaJz/
1I29va0acrCByVSaeNXpGc872OB+PPVjmDkvucJeEQKBgQD7xuP0IllvpicF8KnM
TzBgUMUyBOEltjthHdqS6oPJX/McPi/qWaE5mw1rSSm5lVQPIoTOHrPgUOxRMm4b
dHVXjln8rhVeryAFrElhj7w5k7j9XU5QfAseQK+RBEggAwUZk7/wHHsScHGrCKl5
3pnBB0Ce6KrptjQKg9UrIc/S3wKBgQDno/h75WVfMTYjja/D+9zL6P8FaWibI6Mg
x8yKiAuTDQ+rjxPRgPYjhSJBw3cptD2Ey0V8J2NWG/EjgCxgNlq+rzZxnUCTqdMK
Nt3DSk0BA+LNmCgnKCg/zNq7w2XHdjDTc0rfeOXt5fq7wX8lunACn/95vzvr99/u
9HLlz3KmiwKBgBVaOr7bouYbGzgfvua62IlykCa7zzRZjhOgaocHKIINhxqgE4Q2
cbvm8G5m2AkLJwPZk5W/eNXPRxtjwX7Gk6UHR45sXReYloikodyKShY/9vJV1Wxx
+KdqKPmNeWhtmSMgKqj8YVug+aLdqzHQtQ1vxgU0Cjqj3yn9IDj2Nx/VAoGAO6tf
bPrwnA7fNVVgO4n7nINOfiRjD+OkN+N/6weUg7LPoI/guQ0RWqEG7A3f+lw1pKmA
IrU6v4m/GjgANmCKC6iyy52IbwFGHdF4WsAfCe3oVLGnVj7f719j0Q5Kf5EQjsea
N+q6wAeICSmVCTD3fZWdh80dMHHPu4w4tL41eHUCgYAdE0mWUwkGH09e1tQnXVzG
WKUwd8Te2tfSfzKoNd02FEfk81hzT6o0LGrbS4pCHNFA8rzqmiYHfV/WYRjryMGs
BbzxUwwJnxGJEInlCAeM4t71M3tPR85DDJB1PfpWf0Fc5YvlDQIYeYt1o+QdWLBL
lL9mcioBzU98UA7jP86GAQ==
-----END PRIVATE KEY-----
EOF
}
#######################
# Start               #
#######################
echo -e "\e[36m +--------------------------------------+"
echo -e "\e[36m | $(date)         |"
echo -e "\e[36m | Starting ELK Install Script          |"
echo -e "\e[36m | ELK Stack for Debian based systems   |"
echo -e "\e[36m |\e[1m E\e[22mlastic - \e[1mL\e[22mogstash - \e[1mK\e[22mibana          |"
echo -e "\e[36m +--------------------------------------+"
echo ""
echo -e " \e[1;4;34mELK Installer Status\e[0m"
echo ""

checkpriv
#echo -e "\e[33m [-] System Update...\e[0m"
#apt update &> /dev/null
#apt upgrade -y &> /dev/null
#echo -e "\e[32m [\xE2\x9C\x94] System Update - Complete\e[0m"
echo -e "\e[33m [!] Adding the elasticsearch repo \e[0m"
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - &> /dev/null
echo -e "\e[32m [\xE2\x9C\x94] elastic Gnu Privacy Guard key added successfully \e[0m"

apt install apt-transport-https -y &> /dev/null
echo -e "\e[32m [\xE2\x9C\x94] apt-transport-https successfully \e[0m"

echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" > /etc/apt/sources.list.d/elastic-7.x.list
echo -e "\e[32m [\xE2\x9C\x94] elastic Repo added to source list successfully \e[0m"

apt update &> /dev/null
echo -e "\e[32m [\xE2\x9C\x94] apt repo list updated\e[0m"



echo -e "\e[33m [!] Installing pre-requisites, this can take a few minutes \e[0m"
getreq "curl"
getreq "elasticsearch"
getreq "kibana"
getreq "openjdk-14-jre"
#getreq "openjdk-8-jdk"
getreq "logstash"


read -p "Press any key to resume..."

## Config Stage ##

#######################
# Disable IPv6        #
#######################

echo "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
sysctl -p > /dev/null

#######################
# elasticsearch       #
#######################
echo -e "\e[33m [!] Configuring elasticstack\e[0m"
## backup vanilla/existing elasticsearch directory
tar -czvf /etc/elasticsearch/elasticsearch_$(date +'%F_%H-%M-%S').tar.gz /etc/elasticsearch/ * &> /dev/null
sleep 0.5
## backup vanilla/existing elastic config
mv /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.original
## set java memory requirements. Where -Xms3g is; is 3GB assuming you have 6GB of RAM. This should be set to half what your instance has.
cp /etc/elasticsearch/jvm.options /etc/elasticsearch/jvm.options.original
sed -i 's/-Xms1g/-Xms3g/g' /etc/elasticsearch/jvm.options
sed -i 's/-Xmx1g/-Xmx3g/g' /etc/elasticsearch/jvm.options
echo -e "\e[32m [\xE2\x9c\x94] elasticsearch JVM heapsize set to 3GB. This should be aproximately half of the system memory available.\e[0m"

echo -e "\e[33m [-] elasticsearch.yml\e[0m"
cat <<"EOF"> /etc/elasticsearch/elasticsearch.yml
node.name: hostname
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
bootstrap.memory_lock: true
network.host: x.x.x.x
http.host: x.x.x.x
http.port: 9200

discovery.seed_hosts:
   - 0.0.0.0:9300
   - x.x.x.x:9300

cluster.initial_master_nodes:
   - x.x.x.x:9300
EOF

sed -i "s/network.host: x.x.x.x/network.host: ${ip}/g" /etc/elasticsearch/elasticsearch.yml
echo -e "\e[32m --> [\xE2\x9c\x94] network.host changed to ${ip}\e[0m"
sed -i "s/node.name: hostname/node.name: ${HOSTNAME}/g" /etc/elasticsearch/elasticsearch.yml
echo -e "\e[32m --> [\xE2\x9c\x94] node.name changed to ${HOSTNAME}\e[0m"
sed -i "s/http.host: x.x.x.x/http.host: ${ip}/g" /etc/elasticsearch/elasticsearch.yml
echo -e "\e[32m --> [\xE2\x9c\x94] http.host changed to ${ip}\e[0m"
sed -i "s/   - x.x.x.x:9300/   - ${ip}:9300/g" /etc/elasticsearch/elasticsearch.yml
echo -e "\e[32m --> [\xE2\x9c\x94] discovery.seed_hosts: changed to ${ip}:9300\e[0m"
echo -e "\e[32m --> [\xE2\x9c\x94] cluster.initial_master_nodes: changed to ${ip}:9300\e[0m"

echo -e "\e[32m [\xE2\x9c\x94] elasticsearch YAML config file updated\e[0m"


## elasticsearch memlock fix
echo -e "\e[32m [\xE2\x9c\x94] Configuring elasticsearch memlock\e[0m"
if [ ! -d "/etc/systemd/system/elasticsearch.service.d" ]
then
    mkdir "/etc/systemd/system/elasticsearch.service.d"
        touch "/etc/systemd/system/elasticsearch.service.d/override.conf"
        cat <<"EOF" > /etc/systemd/system/elasticsearch.service.d/override.conf
[Service]
LimitMEMLOCK=infinity
EOF
else
    if [ ! -f "/etc/systemd/system/elasticsearch.service.d/override.conf" ]
    then
        touch "/etc/systemd/system/elasticsearch.service.d/override.conf"
                cat <<"EOF" > /etc/systemd/system/elasticsearch.service.d/override.conf
[Service]
LimitMEMLOCK=infinity
EOF
    fi
fi
echo -e "\e[32m [\xE2\x9c\x94] Elasticsearch memlock fix applied\e[0m"

## start elasticsearch
systemctl enable elasticsearch.service &> /dev/null
initialCheckSvc "elasticsearch" ${ip}
checkPort "9200" ${ip}

read -p "Press any key to resume..."


#######################
# kibana              #
#######################
echo -e "\e[33m [-] kibana.yml\e[0m"
## backup vanilla/existing kibana directory
tar -czvf /etc/kibana/kibana_$(date +'%F_%H-%M-%S').tar.gz /etc/kibana/ * &> /dev/null
mv /etc/kibana/kibana.yml /etc/kibana/kibana.yml.original

cat <<"EOF" > /etc/kibana/kibana.yml
server.port: 5601
server.host: localhost
server.publicBaseUrl: "http://localhost:5601"
elasticsearch.hosts: ["http://localhost:9200"]

EOF

sed -i "s/server.host: localhost/server.host: ${ip}/g" /etc/kibana/kibana.yml
echo -e "\e[32m --> [\xE2\x9c\x94] server.host set to ${ip} \e[0m"
sed -i "s/server.publicBaseUrl: \"http:\/\/localhost:5601\"/server.publicBaseUrl: \"http:\/\/${ip}:5601\"/g" /etc/kibana/kibana.yml
echo -e "\e[32m --> [\xE2\x9c\x94] server.publicBaseUrl: changed to http://${ip}:5601\e[0m"
sed -i "s/elasticsearch.hosts: \[\"http:\/\/localhost:9200\"]/elasticsearch.hosts: \[\"http:\/\/${ip}:9200\"]/g" /etc/kibana/kibana.yml
echo -e "\e[32m --> [\xE2\x9c\x94] elasticsearch.hosts changed to http://${ip}:9200\e[0m"

## start kibana
systemctl enable kibana.service &> /dev/null
initialCheckSvc "kibana" ${ip}
checkPort "5601" ${ip}

read -p "Press any key to resume..."

#######################
# logstash            #
#######################
echo -e "\e[33m [-] logstash.yml\e[0m"
## backup vanilla/existing logstash directory
tar -czvf /etc/logstash/logstash$(date +'%F_%H-%M-%S').tar.gz /etc/logstash/ * &> /dev/null
## backup vanilla/existing logstash config
cp /etc/logstash/logstash.yml /etc/logstash/logstash.yml.original

sed -i "s/# node.name: test/node.name: ${HOSTNAME}/g" /etc/logstash/logstash.yml
echo -e "\e[32m --> [\xE2\x9c\x94] node.name changed to ${HOSTNAME}\e[0m"
sed -i "s/# http.host: 127.0.0.1/http.host: ${ip}/g" /etc/logstash/logstash.yml
echo -e "\e[32m --> [\xE2\x9c\x94] http.host changed to ${ip}\e[0m"
touch /etc/logstash/conf.d/auditbeat.conf
#echo "## INPUTS SECTION
#input {
#       beats {
#               ports => 5044
#       }
#}
## OUTPUTS SECTION
#output {
#       elasticsearch {
#               hosts => ["http://${ip}:9200"]
#               index => "%{[@metadata][beat]-%{-YYYY.MM.dd}"
##      }
#}" > /etc/logstash/conf.d/auditbeat.conf

################# uncomment this bit
echo "input {
  beats {
    host => \"${ip}\"
    port => 5044
  }
}" > /etc/logstash/conf.d/02-beats-input.conf

echo "output {
  if [@metadata][pipeline] {
    elasticsearch {
    hosts => [\"${ip}:9200\"]
    manage_template => false
    index => \"%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}\"
    pipeline => \"%{[@metadata][pipeline]}\"
    }
  } else {
    elasticsearch {
    hosts => [\"${ip}:9200\"]
    manage_template => false
    index => \"%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}\"
    }
  }
}" > /etc/logstash/conf.d/30-elasticsearch-output.conf
#sed -i "s/localhost:9200/${ip}:9200/g" /etc/logstash/conf.d/02-beats-input.conf
#sed -i "s/hosts => ip/hosts => ${ip}/g" /etc/logstash/conf.d/logstash-simple.conf
####################### till this

#cat <<"EOF" > /etc/logstash/conf.d/logstash-simple.conf
#input {
#  beats {
#       hosts => ip
#    port => 5044
#    ssl => true
#    ssl_certificate => "/etc/logstash/certs/logstash.crt"
#    ssl_key => "/etc/logstash/certs/logstash.key"
#    ssl_verify_mode => "force_peer"
#    ssl_certificate_authorities => ["/etc/logstash/certs/ca.crt"]
#  }
#}
#output {
#  elasticsearch { hosts => ["localhost:9200"] }
#  stdout { codec => rubydebug }
#}
#EOF

#sed -i "s/localhost:9200/${ip}:9200/g" /etc/logstash/conf.d/logstash-simple.conf
#sed -i "s/hosts => ip/hosts => ${ip}/g" /etc/logstash/conf.d/logstash-simple.conf

### logstash certificates
## first define the reference hashes
cahash="6e3a0e0964849ca813398f548f53fe8b9af897ea383d24b1e20103053aba2c6c"
crthash="cccd412916868dffcbdc6c8fc159315d36c1aa6310d087a55e7c25750ab48ef1"
keyhash="d22428de13b84eb8b9c173fc5fa24ee42b176f019ceaf52e8d4829d24f6d92bd"
## check if the certs directory already exists, then check if the ca.crt/logstash.crt/logstash.key exists,
## matches the reference hashes and either moves the old one and imports the new certs and key
if [ ! -d "/etc/logstash/certs" ]; then
        echo "certs dir doesn't exist"
        mkdir /etc/logstash/certs/
        chmod 755 /etc/logstash/certs/
        generate-cacert
        generate-logstashcert
        generate-logstashkey
elif [ "$(ls -A '/etc/logstash/certs')" ]; then
        echo "certs dir does exist "
        tar -czvf /etc/logstash/certs$(date +'%F_%H-%M-%S').tar.gz /etc/logstash/ * &> /dev/null
        rm -rf /etc/logstash/certs/*
        generate-cacert
        generate-logstashcert
        generate-logstashkey
fi
## start logstash
systemctl enable logstash.service &> /dev/null
initialCheckSvc "logstash" ${ip}
checkPort "5044" ${ip}

read -p "Press any key to resume..."

echo -e "\e[32m Elastic, Logstash and Kibana has been installed, \nyou can reach the kibana dashboard via http://${ip}:5601 or a hostname if you have defined one. \nYou now need to configure your agents...\e[0m"
