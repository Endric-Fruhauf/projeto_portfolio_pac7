# Wickedbotz Access Control System

Projeto de Portfólio (PAC VII/VIII - 2026) | Centro Universitário Católica de Santa Catarina

**Python • Flask • MySQL • REST API • Control iD iDFace**

---

# Sobre o Projeto

O Wickedbotz Access Control System é uma solução de controle de acesso desenvolvida para atender às necessidades da equipe de robótica Wickedbotz.

O projeto utiliza reconhecimento facial através do equipamento Control iD iDFace, integrado a um servidor local responsável pelo gerenciamento de usuários, controle de permissões e registro de acessos.

O objetivo é substituir a dependência de chaves físicas por um sistema mais seguro, centralizado e adequado à realidade da equipe.

---

# O Problema

Atualmente, o acesso ao laboratório depende da utilização de chaves físicas.

Esse modelo apresenta algumas limitações:

* Quantidade limitada de cópias da chave;
* Dependência de membros específicos para liberar acesso;
* Possibilidade de perda ou esquecimento das chaves;
* Dificuldade para identificar quem acessou o ambiente;
* Ausência de registros centralizados de entrada e saída.

Essas situações podem dificultar o acesso dos membros ao laboratório e reduzir a rastreabilidade dos acessos realizados.

---

# A Solução

O sistema proposto substitui a autenticação baseada em chaves físicas por reconhecimento facial.

Os membros autorizados podem acessar o ambiente utilizando apenas sua biometria facial cadastrada no dispositivo.

Além disso, administradores possuem acesso a uma interface de gerenciamento que permite controlar usuários, visualizar registros de acesso e realizar ações administrativas de forma centralizada.

---

# Por que não utilizar apenas o software do fabricante?

O equipamento Control iD iDFace já oferece recursos de autenticação facial, porém seu software é uma solução genérica voltada para diferentes cenários de mercado.

O Wickedbotz Access Control System atua como uma camada complementar de gerenciamento, oferecendo funcionalidades adaptadas às necessidades da equipe, como:

* Controle simplificado de membros;
* Registro centralizado de acessos;
* Controle de permissões administrativas;
* Abertura remota da porta;
* Maior flexibilidade para futuras personalizações;
* Operação totalmente local.

Dessa forma, o projeto aproveita a robustez do dispositivo iDFace enquanto oferece uma experiência personalizada para a equipe.

---

# Arquitetura do Sistema

O sistema segue uma arquitetura cliente-servidor composta por três componentes principais.

## Dispositivo de Acesso

* Control iD iDFace
* Reconhecimento facial
* Validação biométrica dos usuários

## Comunicação Local

* Conexão via rede local (Ethernet)
* Comunicação direta entre iDFace e servidor
* Operação sem dependência de serviços externos

## Servidor Local

* API REST
* Gerenciamento de usuários
* Controle de permissões
* Registro de acessos
* Persistência de dados

## Interface Administrativa

* Cadastro de usuários
* Consulta de acessos
* Controle administrativo
* Abertura remota da porta

---

# Fluxo de Funcionamento

1. O usuário aproxima-se do dispositivo iDFace.
2. O equipamento realiza a identificação facial.
3. O iDFace comunica o evento ao servidor local através da rede interna.
4. O servidor registra o acesso no banco de dados.
5. As informações ficam disponíveis no painel administrativo.
6. Administradores podem consultar históricos e realizar ações administrativas, como a abertura remota da porta.

---

# Tecnologias Utilizadas

## Back-end

* Python
* Flask
* REST API

## Banco de Dados

* MySQL

## Hardware

* Control iD iDFace

## Infraestrutura

* Rede Local (Ethernet)
* Servidor Local

## Comunicação

* HTTP/HTTPS
* Integração via API Control iD

---

# Principais Funcionalidades

✅ Cadastro e gerenciamento de usuários

✅ Integração com Control iD iDFace

✅ Reconhecimento facial

✅ Registro de acessos

✅ Controle de permissões administrativas

✅ Abertura remota da porta

✅ Operação local

✅ Histórico de acessos

---

# Diferenciais

* Eliminação da dependência de chaves físicas;
* Comunicação totalmente local entre dispositivo e servidor;
* Registro centralizado dos acessos;
* Operação sem dependência de serviços em nuvem;
* Interface adaptada à realidade da equipe Wickedbotz;
* Controle administrativo simplificado;
* Abertura remota da porta;
* Possibilidade de personalização futura.

---

# Possíveis Evoluções Futuras

* Aplicativo mobile para administradores;
* Notificações em tempo real;
* Dashboard com estatísticas de acesso;
* Relatórios avançados;
* Exportação de registros em PDF e Excel;
* Sistema de visitantes temporários;
* Backup automatizado dos registros;
* Melhorias de usabilidade e experiência do usuário.

---

# Roadmap

## Fase 1

* Estruturação da API REST;
* Modelagem do banco de dados;
* Integração inicial com o iDFace.

## Fase 2

* Cadastro e gerenciamento de usuários;
* Registro de acessos;
* Controle de permissões.

## Fase 3

* Interface administrativa;
* Abertura remota da porta;
* Testes de integração.

## Fase 4

* Relatórios;
* Otimizações;
* Documentação final do projeto.

---

# Autor

**Endric Fruhauf**
Projeto desenvolvido para a disciplina PAC VII/VIII do Centro Universitário Católica de Santa Catarina.
