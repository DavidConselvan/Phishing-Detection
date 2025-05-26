# Ferramenta de Detecção de Phishing

Uma aplicação web abrangente para detectar tentativas de phishing através de análise de URL, aprendizado de máquina e várias verificações de segurança.

## Funcionalidades

### Análise de URL
- Integração com PhishTank para URLs de phishing conhecidas
- Verificação de idade do domínio via WHOIS
- Validação de certificado SSL
- Detecção de DNS dinâmico
- Detecção de similaridade com marcas
- Análise de redirecionamentos suspeitos
- Análise de conteúdo para formulários de login e dados sensíveis

### Aprendizado de Máquina
- Modelo de detecção de phishing baseado em BERT
- Pontuação de confiança
- Análise de múltiplas características (comprimento da URL, subdomínios, caracteres especiais, etc.)
- ref: https://huggingface.co/ealvaradob/bert-finetuned-phishing/tree/main

### Interface do Usuário
- Painel interativo com análise detalhada
- Indicadores visuais para URLs seguras/maliciosas
- Histórico de análises com funcionalidade de exportação
- Visualização de gráficos e estatísticas

## Configuração

### Backend (Python/FastAPI)
1. Navegue até o diretório do backend:
   ```bash
   cd backend-python
   ```
2. Crie e ative o ambiente virtual:
   ```bash
   python -m venv venv
   source venv/bin/activate  # No Windows: venv\Scripts\activate
   ```
3. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```
4. Inicie o servidor:
   ```bash
   uvicorn app.main:app --reload --port 3001
   ```
   ### A porta 3001 é obrigatória!

### Frontend (React/TypeScript)
1. Navegue até o diretório do frontend:
   ```bash
   cd frontend
   ```
2. Instale as dependências:
   ```bash
   npm install
   ```
3. Inicie o servidor de desenvolvimento:
   ```bash
   npm run dev
   ```

## Tecnologias
- Backend: Python, FastAPI
- Frontend: React, TypeScript, Tailwind CSS, Vite
- ML: BERT, Transformers
- Visualização: Recharts
