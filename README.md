### **Projeto: Site Full-Stack com Criptografia de Ponta a Ponta**

Este projeto é uma aplicação web full-stack que demonstra um fluxo de comunicação segura entre o cliente (frontend) e o servidor (backend) utilizando criptografia assimétrica (chave pública/privada).

#### **Objetivo**

O objetivo principal é garantir que os dados enviados pelo usuário através do navegador sejam criptografados no lado do cliente antes de serem transmitidos pela rede. O servidor, e somente ele, é capaz de descriptografar e ler a informação original, protegendo os dados contra interceptações.

#### **Como Funciona**

1.  **Geração das Chaves**: O script `generateKeys.js` cria um par de chaves RSA:
    *   `public.pem`: Chave pública, que pode ser distribuída abertamente.
    *   `private.pem`: Chave privada, que deve ser mantida em segredo absoluto no servidor.

2.  **Frontend (Cliente)**:
    *   A página (`public/index.html`) e seu script (`public/script.js`) representam a interface do usuário.
    *   O frontend obtém a `public.pem`.
    *   Quando o usuário envia uma informação, o `script.js` utiliza a chave pública para criptografar os dados diretamente no navegador.

3.  **Backend (Servidor)**:
    *   O servidor Node.js (`server.js`) expõe a aplicação na web.
    *   Ao receber uma requisição com dados do cliente, o backend utiliza a `private.pem` (que só ele possui) para descriptografar a mensagem.
    *   Após descriptografar, o servidor pode processar a informação em seu formato original (texto plano).

#### **Estrutura**

*   `server.js`: Arquivo principal do servidor Node.js (provavelmente usando Express ou um módulo HTTP nativo).
*   `generateKeys.js`: Ferramenta para gerar o par de chaves criptográficas.
*   `public/`: Pasta com os arquivos do frontend que são servidos aos usuários.
    *   `index.html`: Estrutura da página.
    *   `script.js`: Lógica do cliente, incluindo a função de criptografia.
*   `keys/`: Diretório no backend para armazenar de forma segura as chaves do servidor.

#### **Tecnologias**

*   **Backend**: Node.js
*   **Frontend**: HTML, CSS, JavaScript
*   **Criptografia**: Módulo `crypto` do Node.js para operações com chaves RSA.
