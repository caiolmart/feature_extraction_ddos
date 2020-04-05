# distributed_ddos

##  Origem dos dados

Esse dataset foi gerado por um [paper](https://ieeexplore.ieee.org/document/8888419) que buscava trazer uma nova forma de classificar ataques DDoS e gerar um dataset moderno que fosse descritivo desse tipo de ataque, toda a motivacao partiu da inesistencia de um dataset satisfatorio. 

Resumindo o trabalho realizado, eles simularam um trafego padrao, que eles chamaram de benigno, a partir de um perfil gerado em cima de dados de usuarios reais. Uma vez criado esse stream benigno de pacotes, eles criaram uma rede capaz de gerar diversos tipos de ataques DDoS distintos e capturaram todos os pacotes que chegavam na rede vitima. A ideia eh que agora eles possuem um dataset proximo o suficiente da realidade para ser utilizado em tarefas mais complicadas como deteccao de ataques e a classificacao deles. Esse dataset de treino possui 11 tipos de ataques, no paper e [na descricao dos dados](https://www.unb.ca/cic/datasets/ddos-2019.html) eles citam 12 tipos de ataques mas nunca explicam de maneira compreensivel porque o dataset possui um cenario a menos, "*The traffic volume for WebDDoS was so low and PortScan just has been executed in the testing day and will be unknown for evaluating the proposed model*". O ataque faltando eh o WebDDoS . 
Os pacotes capturados foram armazendos no formato PCAP e em seguida foram tratados por uma ferramenta chamada [CICFlowMeter](https://github.com/ahlashkari/CICFlowMeter). Essa ferramente pega os PCAPS e gera o "flow" dos pacotes para poder extrair features dos flows. [Aqui](https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt) pode ser encontrado uma lista completa das features geradas por essa ferramenta, o nosso dataset possui apenas um recorte de 80 destas features. A escolha das features nao foi justificada no trabalho original.

Com o dataset de treino em maos, os autores geraram um novo conjunto de ataques com apenas 7 categorias desta vez, 6 delas presentes no conjunto de treino e uma categoria de ataque nova (referido como PortScan no paper e Portmap nos dados). Os autores realizaram uma preanalise onde decidiram quais seriam as features mais relevantes atraves do uso de uma random forest e por fim eles realizaram testes com 4 modelos diferentes (ID3, Random Forest, Naive Bayes, Multinomial Logistic Regression) para tentar detectar ataques DDoS no conjunto de teste. Nem o codigo nem os parametros utilizados foram compartilhados no trabalho original.



## DataSet
|          | CSV   | PCAP.zip |
|----------|-------|----------|
| **Treino** | 22Gb  | 20.9Gb   |
| **Teste** | 8.7Gb | 2.0Gb    |

Os conjuntos em formato CSV possuem um arquivo CSV por categoria de ataque realizado.

Os conjuntos em formato PCAP.zip sao compostos por uma colecao de arquivos PCAP de 200Mb cada e organizados de maneira sequencial representando a totalidade dos pacotes transmitidos.
Os dados PCAP nao comprimidos estao na ordem centenas de Gb e nao cabem no disco da maquina disponivel.


_____
incluir analises do pandas aqui talvez?
_________



## Criticas ao dataset e seu paper

-A ferramenta utilizada para processar os dados, CICFlowMeter, foi desenvolvida pelos proprios autores do paper no passado e nao parece ter sido utilizada por muitos outros pesquisadores. Ela eh aberta num repositorio do github porem nao possui documentacao relevante e sofre de diversas m'as praticas de programacao.

-Geracao dos CSVs apartir dos PCAPS nao eh repoduzivel, nao compartilharam codigo ou parametros utilizados

-Reproducao dos modelos preditivos e suas metricas nao eh reproduzivel, nao compartilham codigo ou parametros utilizados. 

-Nao esta claro como os modelos foram testados, a existencia de uma classe nova no conjunto de treino nos leva a imaginar que os modelos tem como objetivo detectar se ha um ataque DDoS ocorrendo ou nao sem se importar com classifica-lo. Porem eles se utilizam de um modelo de regressao logistica multinomial, o que nos leva a acreditar que os modelos buscavam detectar e classificar o tipo de ataque. Se esse for o caso, nao conseguimos compreender a motivacao por incluir uma nova classe no cojunto de teste que nao estava presente no conjunto de treino para um classificador.

-O paper possui diversos erros de digitacao e por vezes eh pouco claro.

-Todos os modelos utilizados foram testados a posteriori e nao sao capazes de detectar um ataque em tempo real.


## Ideias possiveis de serem exploradas em nosso paper


-Gerar um modelo "online" capaz de receber o stream de dados e detectar ataques em tempo real.

-Explorar o desbalanceamento das classes, a proporcao de pacotes benignos para pacotes malignos eh extremamente desbalanceada.

-Explorar os dados nao processados e gerar novas features a partir dos PCAPS que poderiam se mostrar mais relevantes do que as utilizadas nesse dataset.

-Explorar algoritmos mais modernos do que os testados nesse paper.


