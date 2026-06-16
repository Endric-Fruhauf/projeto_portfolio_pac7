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

- Quantidade limitada de cópias da chave;
- Dependência de membros específicos para liberar acesso;
- Possibilidade de perda ou esquecimento das chaves;
- Dificuldade para identificar quem acessou o ambiente;
- Ausência de registros centralizados de entrada e saída.

Essas situações impactam diretamente a rastreabilidade e o controle de acesso ao ambiente.

---

# A Solução

O sistema proposto substitui a autenticação baseada em chaves físicas por reconhecimento facial.

Os membros autorizados podem acessar o ambiente utilizando sua biometria facial cadastrada no dispositivo.

Além disso, administradores possuem uma interface de gerenciamento que permite controlar usuários, visualizar registros de acesso e realizar ações administrativas de forma centralizada.

---

# Por que não utilizar apenas o software do fabricante?

O equipamento Control iD iDFace já oferece recursos de autenticação facial, porém seu software é uma solução genérica voltada para diferentes cenários de mercado.

O Wickedbotz Access Control System atua como uma camada complementar de gerenciamento, oferecendo funcionalidades adaptadas às necessidades da equipe:

- Controle simplificado de membros;
- Registro centralizado de acessos;
- Controle de permissões administrativas;
- Abertura remota da porta;
- Operação totalmente local;
- Maior flexibilidade para personalizações futuras.

---

# Arquitetura do Sistema

O sistema segue uma arquitetura cliente-servidor composta por três componentes principais.

## Dispositivo de Acesso

- Control iD iDFace
- Reconhecimento facial
- Validação biométrica dos usuários

## Comunicação Local

- Rede local (Ethernet)
- Comunicação direta entre iDFace e servidor
- Operação sem dependência de serviços externos

## Servidor Local

- API REST em Python (Flask)
- Gerenciamento de usuários
- Controle de permissões
- Registro de acessos
- Persistência de dados

## Interface Administrativa

- Cadastro de usuários
- Consulta de acessos
- Controle administrativo
- Abertura remota da porta

---
# Fluxo de Funcionamento

1. O usuário aproxima-se do dispositivo iDFace;
2. O equipamento realiza a identificação facial;
3. Caso a autenticação seja validada, o dispositivo libera a abertura da porta;
4. O iDFace comunica o evento ao servidor local através da rede interna;
5. O servidor registra o acesso no banco de dados;
6. As informações ficam disponíveis no painel administrativo;
7. Administradores podem consultar históricos de acesso e realizar ações administrativas, como a abertura remota da porta.
---

# Tecnologias Utilizadas

## Back-end

- Python
- Flask
- REST API

## Banco de Dados

- MySQL

## Hardware

- Control iD iDFace

## Infraestrutura

- Rede Local (Ethernet)
- Servidor Local

## Comunicação

- HTTP/HTTPS
- Integração via API Control iD

---

# Estrutura do Projeto

![Arquitetura do Sistema](docs/arquitetura.png.png)

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

# API (Resumo de Endpoints)

| Método | Endpoint | Função |
|----------|----------|----------|
| POST | /users | Cadastro de usuários |
| GET | /users | Listagem de usuários |
| PUT | /users/{id} | Atualização de usuários |
| DELETE | /users/{id} | Remoção de usuários |
| POST | /access/log | Registro de acesso |
| POST | /auth/facial | Autenticação facial |
| POST | /door/open | Abertura remota da porta |

---

# Modelo de Dados (Resumo)

## users

- id
- nome
- id_facial
- permissao

## access_logs

- id
- user_id
- data_hora
- resultado

## permissions

- id
- tipo
- descricao

---

# Diferenciais

- Eliminação da dependência de chaves físicas;
- Comunicação totalmente local entre dispositivo e servidor;
- Registro centralizado dos acessos;
- Operação sem dependência de serviços em nuvem;
- Interface adaptada à realidade da equipe Wickedbotz;
- Controle administrativo simplificado;
- Abertura remota da porta;
- Possibilidade de personalização futura.

---

# Limitações do Sistema

- Dependência do hardware Control iD iDFace;
- Escalabilidade limitada em ambientes com múltiplos pontos de acesso;
- Dependência da infraestrutura de rede local;
- Possíveis falhas de reconhecimento em condições inadequadas de iluminação;
- Possibilidade de falsos positivos ou falsos negativos inerentes à biometria facial.

---

# Possíveis Evoluções Futuras

- Aplicativo mobile para administradores;
- Notificações em tempo real;
- Dashboard com estatísticas de acesso;
- Relatórios avançados;
- Exportação de registros em PDF e Excel;
- Sistema de visitantes temporários;
- Backup automatizado dos registros;
- Melhorias de usabilidade e experiência do usuário.

---

# Status do Projeto

## Em Desenvolvimento

- Levantamento de requisitos concluído;
- Arquitetura definida;
- Modelagem do banco de dados em andamento;
- Estudo da API Control iD iDFace em andamento;
- Desenvolvimento da API REST previsto no cronograma.


# Cronograma (PAC VII/VIII)

### Semanas 1–3

- Levantamento de requisitos do sistema;
- Pesquisa sobre soluções de controle de acesso;
- Estudo da API do Control iD iDFace;
- Modelagem inicial do banco de dados MySQL;
- Definição da arquitetura cliente-servidor;
- Elaboração da documentação inicial do projeto.

### Semanas 4–7

- Desenvolvimento da API REST em Python;
- Estruturação do banco de dados;
- Implementação do cadastro de usuários;
- Desenvolvimento do sistema de permissões administrativas;
- Testes iniciais das rotas da API;
- Atualização da documentação técnica.

### Semanas 8–12

- Integração entre o servidor local e o Control iD iDFace;
- Sincronização de usuários entre sistema e dispositivo;
- Registro automatizado dos eventos de acesso;
- Implementação das regras de autenticação;
- Validação da comunicação entre dispositivo e servidor;
- Atualização da documentação do projeto.

### Semanas 13–15

- Desenvolvimento do painel administrativo web;
- Consulta e filtragem de registros de acesso;
- Gerenciamento de usuários;
- Implementação da abertura remota da porta;
- Refinamento da interface;
- Atualização da documentação técnica.

### Semanas 16–18

- Testes de integração entre todos os componentes;
- Correção de falhas identificadas;
- Otimização de desempenho;
- Validação dos requisitos funcionais;
- Atualização da documentação do projeto.

### Semanas 19–20

- Consolidação dos resultados obtidos;
- Revisão do artigo e da documentação;
- Ajustes solicitados pelo orientador;
- Preparação da apresentação final;
- Entrega do projeto.

---

# Autor

**Endric Fruhauf**

Projeto desenvolvido para a disciplina PAC VII/VIII do Centro Universitário Católica de Santa Catarina.
