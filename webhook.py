import os
import hmac
import hashlib
from flask import Flask, request, abort
from dotenv import load_dotenv

# Carrega as variáveis do arquivo .env
load_dotenv()

app = Flask(__name__)

# --- Função de verificação de segurança (mantém a mesma) ---
def verify_signature(secret, payload, signature_header):
    """Verifica a assinatura do webhook."""
    if not signature_header:
        return False
    
    hash_signature = 'sha256=' + hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(hash_signature, signature_header)

# --- Lógica para criar as rotas dinamicamente ---
def get_projects_config():
    """Lê as variáveis de ambiente e retorna um dicionário de projetos."""
    projects = {}
    
    # Itera sobre todas as variáveis de ambiente
    for key, value in os.environ.items():
        if key.endswith('_SECRET'):
            # Encontra as variáveis de segredo
            project_name = key.replace('WEBHOOK_', '').replace('_SECRET', '').lower()
            script_key = f'WEBHOOK_{project_name.upper()}_SCRIPT'
            
            # Se o script correspondente existir, adiciona o projeto
            if os.getenv(script_key):
                projects[project_name] = {
                    'secret': value,
                    'script': os.getenv(script_key)
                }
    return projects

def create_webhook_routes():
    """Cria dinamicamente as rotas do Flask com base na configuração dos projetos."""
    projects_config = get_projects_config()
    
    if not projects_config:
        print("Atenção: Nenhum projeto encontrado no arquivo .env!")

    def generic_webhook_handler(project_name):
        """Função genérica para lidar com o webhook."""
        project = projects_config.get(project_name)
        if not project:
            return "Projeto não configurado", 404
        
        # Verifica a segurança da requisição
        if not verify_signature(project['secret'], request.data, request.headers.get('X-Hub-Signature-256')):
            abort(403)
        
        # Executa o script do projeto
        os.system(project['script'])
        return 'OK', 200

    # Adiciona uma rota para cada projeto de forma programática
    for project_name in projects_config:
        app.add_url_rule(
            f'/webhook/{project_name}',
            endpoint=f'webhook_{project_name}', # Nome único para a rota
            view_func=lambda name=project_name: generic_webhook_handler(name),
            methods=['POST']
        )

# --- Execução principal do script ---
if __name__ == '__main__':
    create_webhook_routes() # Chama a função para criar as rotas antes de iniciar o servidor
    app.run(host='0.0.0.0', port=5000)