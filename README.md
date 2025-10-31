# 👋🏻 Leonardo de Moura Fuseti

Estudante de Defesa Cibernetica no Polo Estacio Piumhi MG . Formação tecnica em Tecnico em Redes de Computadores no IFMG Bambui MG , intusiasta na programação gostando muito de Python e evoluindo dia a dia .

### Conecte-se comigo

[![Perfil DIO](https://img.shields.io/badge/-Meu%20Perfil%20na%20DIO-30A3DC?style=for-the-badge)](https://www.dio.me/users/mourafuseti)
[![E-mail](https://img.shields.io/badge/-Email-000?style=for-the-badge&logo=microsoft-outlook&logoColor=E94D5F)](mailto:mourafuseti@gmail.com)
[![LinkedIn](https://img.shields.io/badge/-LinkedIn-000?style=for-the-badge&logo=linkedin&logoColor=30A3DC)](https://www.linkedin.com/in/leonardo-moura-fuseti-4052b0359/)

### Habilidades

![HTML](https://img.shields.io/badge/HTML-000?style=for-the-badge&logo=html5&logoColor=30A3DC)
![CSS3](https://img.shields.io/badge/CSS3-000?style=for-the-badge&logo=css3&logoColor=E94D5F)
![JavaScript](https://img.shields.io/badge/JavaScript-000?style=for-the-badge&logo=javascript&logoColor=F0DB4F)
![Sass](https://img.shields.io/badge/SASS-000?style=for-the-badge&logo=sass&logoColor=CD6799)
![Bootstrap](https://img.shields.io/badge/bootstrap-000?style=for-the-badge&logo=bootstrap&logoColor=553C7B)
[![Git](https://img.shields.io/badge/Git-000?style=for-the-badge&logo=git&logoColor=E94D5F)](https://git-scm.com/doc)
[![GitHub](https://img.shields.io/badge/GitHub-000?style=for-the-badge&logo=github&logoColor=30A3DC)](https://docs.github.com/)

### GitHub Stats

![GitHub Stats](https://github-readme-stats.vercel.app/api?username=mourafuseti&theme=transparent&bg_color=000&border_color=30A3DC&show_icons=true&icon_color=30A3DC&title_color=E94D5F&text_color=FFF)

# 🛡️ WiFi Auditor Pro v8.1 - Ferramenta de Análise de Segurança Wireless (GUI)

Este projeto é uma ferramenta de teste de penetração (pentest) Wi-Fi automatizada, reestruturada com uma Interface Gráfica de Usuário (GUI) usando a biblioteca `tkinter`.

**Atenção:** Esta ferramenta foi desenvolvida para ambientes de auditoria de segurança em redes das quais você possui **autorização explícita**. O uso em redes não autorizadas é ilegal e antiético. O desenvolvedor não se responsabiliza por qualquer uso indevido.

---

## 🎯 Funcionalidades Principais

* **Interface Gráfica (GUI):** Fácil navegação em ambiente gráfico (não mais apenas console).
* **Log em Tempo Real:** Área dedicada para visualizar o output dos comandos (`airodump-ng`, `aircrack-ng`, etc.) em tempo real, rodando em threads para manter a GUI responsiva.
* **Múltiplos Ataques:** Fluxos de ataque separados e dedicados:
    * Handshake (WPA/WPA2) + Cracking (Aircrack-ng).
    * PMKID Capture (simulado).
    * WPS Pixie-Dust e Brute-Force (simulado).
* **Ataque em Massa:** Capacidade de executar o ataque selecionado em todas as redes escaneadas.
* **Configuração Simplificada:** Configuração de Interface de Monitoramento e Wordlist diretamente na GUI.

## ⚙️ Pré-requisitos

Esta ferramenta foi projetada para ser executada em um ambiente Linux (preferencialmente **Kali Linux** ou similar) com permissões de root.

1.  **Python:** Python 3.x instalado.
2.  **Tkinter:** A biblioteca gráfica padrão do Python.
    ```bash
    sudo apt update
    sudo apt install python3-tk
    ```
3.  **Ferramentas Aircrack-ng Suite:**
    * `airmon-ng`
    * `airodump-ng`
    * `aircrack-ng`
    * `aireplay-ng`
    * *(Outras ferramentas como `hcxdumptool`, `reaver`, etc., devem ser instaladas separadamente para a funcionalidade completa de WPS/PMKID).*

---

## 🚀 Como Executar

### 1. Salvar o Script

Salve o código Python completo no seu sistema, por exemplo, como `/home/kali/auditoria/auditor_de_rede.py`.

### 2. Definir Permissões

Você precisa de permissão de execução para o script e permissões de root para manipular interfaces wireless.

```bash
cd /home/kali/auditoria
chmod +x auditor_de_rede.py
