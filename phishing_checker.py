import base64
import requests
import os
import platform
from datetime import datetime

try:
    import tkinter as tk
    from tkinter import scrolledtext, messagebox
    TK_AVAILABLE = True
except ImportError:
    TK_AVAILABLE = False

if platform.system() == "Windows":
    import winsound

# Recupera a API key da variável de ambiente
api_key = os.getenv("VIRUSTOTAL_API_KEY")

if not api_key:
    raise ValueError("API key ausente! Verifique se ela está definida como variável de ambiente.")

def encode_url_to_base64(url):
    url_bytes = url.encode('utf-8')
    base64_bytes = base64.urlsafe_b64encode(url_bytes)
    return base64_bytes.decode('utf-8').strip('=')

def check_with_virustotal(api_key, input_value):
    headers = {
        "x-apikey": api_key
    }

    if os.path.isfile(input_value):
        with open(input_value, "rb") as file:
            files = {"file": (os.path.basename(input_value), file)}
            api_url = "https://www.virustotal.com/api/v3/files"
            response = requests.post(api_url, headers=headers, files=files)
            if response.status_code == 200:
                analysis_id = response.json()["data"]["id"]
                result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                result_response = requests.get(result_url, headers=headers)
                return result_response.json() if result_response.status_code == 200 else {"error": f"Error retrieving result: {result_response.status_code}"}
            else:
                return {"error": f"Error: {response.status_code}"}
    else:
        encoded_url = encode_url_to_base64(input_value)
        result_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        response = requests.get(result_url, headers=headers)
        return response.json() if response.status_code == 200 else {"error": f"Error: {response.status_code}"}

def extract_viruses(result):
    names = []
    if "data" in result and "attributes" in result["data"]:
        scans = result["data"]["attributes"].get("last_analysis_results", {})
        for engine, details in scans.items():
            if details.get("category") == "malicious":
                names.append(f"{engine}: {details.get('result')}")
    return names

def generate_report(input_value, result, status):
    """Gera um relatório .txt com o resultado da análise e retorna o caminho do arquivo."""
    timestamp = datetime.now()
    filename = f"relatorio_analise_{timestamp.strftime('%Y%m%d_%H%M%S')}.txt"

    attributes = result.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    virus_names = extract_viruses(result)

    lines = []
    lines.append("--- Relatório de Análise (Security Sentinels) ---")
    lines.append(f"Data/Hora: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Alvo analisado: {input_value}")
    lines.append(f"Status: {status}")
    lines.append("")
    lines.append("Resumo da análise:")
    lines.append(f"  Maliciosos:    {stats.get('malicious', 0)}")
    lines.append(f"  Suspeitos:     {stats.get('suspicious', 0)}")
    lines.append(f"  Inofensivos:   {stats.get('harmless', 0)}")
    lines.append(f"  Não detectado: {stats.get('undetected', 0)}")
    lines.append("")

    if virus_names:
        lines.append("Engines que detectaram ameaça:")
        for v in virus_names:
            lines.append(f"  - {v}")
        lines.append("")
        lines.append("Recomendação: NÃO acesse/execute o alvo marcado como MALICIOSO.")
    else:
        lines.append("Nenhuma engine classificou o alvo como malicioso.")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return filename

def print_result_terminal(result, status):
    """Fallback para ambientes sem display gráfico (ex.: VM Linux headless)."""
    print(f"\n--- Status: {status} ---")
    explanation = "O arquivo/URL é seguro." if status == "Safe" else "Cuidado! O arquivo/URL é malicioso."
    print(explanation)
    virus_names = extract_viruses(result)
    if virus_names:
        print("Detecções:")
        for v in virus_names:
            print(f"  - {v}")
    print("\nResultado completo:")
    print(result)

def alert_popup(result, status):
    if not TK_AVAILABLE:
        print_result_terminal(result, status)
        return
    try:
        root = tk.Tk()
    except tk.TclError:
        print_result_terminal(result, status)
        return

    root.title("VirusTotal Analysis Result")

    window_width = 1000
    window_height = 600
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x_cordinate = int((screen_width / 2) - (window_width / 2))
    y_cordinate = int((screen_height / 2) - (window_height / 2))
    root.geometry(f"{window_width}x{window_height}+{x_cordinate}+{y_cordinate}")

    root.lift()
    root.attributes("-topmost", True)
    root.after(0, lambda: root.attributes("-topmost", False))

    bg_color = "green" if status == "Safe" else "red"
    root.configure(background=bg_color)

    status_label = tk.Label(root, text=f"Status: {status}", font=("Helvetica", 16, "bold"), bg=bg_color)
    status_label.pack(pady=10)

    explanation = "O arquivo/URL é seguro." if status == "Safe" else "Cuidado! O arquivo/URL é malicioso."
    explanation_label = tk.Label(root, text=explanation, font=("Helvetica", 12), bg=bg_color)
    explanation_label.pack(pady=5)

    virus_names = extract_viruses(result)
    if virus_names:
        virus_label = tk.Label(root, text="\n".join(virus_names), font=("Helvetica", 10), bg=bg_color, fg="white")
        virus_label.pack(pady=5)

    text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=110, height=30, font=("Courier", 10))
    text_area.pack(padx=10, pady=10)
    text_area.insert(tk.END, str(result))
    text_area.configure(state='disabled')

    if platform.system() == 'Windows':
        freq = 1000 if status == "Safe" else 2000
        duration = 500
        winsound.Beep(freq, duration)

    root.mainloop()

def main():
    input_value = input("Digite a URL ou o caminho do arquivo a ser analisado: ").strip()
    result = check_with_virustotal(api_key, input_value)

    if isinstance(result, dict) and "error" not in result:
        attributes = result.get('data', {}).get('attributes', {})
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        malicious_count = last_analysis_stats.get('malicious', 0)
        status = "Safe" if malicious_count == 0 else f"Malicious ({malicious_count} reports)"
        print("Result from VirusTotal:", result)
        report_path = generate_report(input_value, result, status)
        print(f"Relatório gerado em: {os.path.abspath(report_path)}")
        alert_popup(result, status)
    else:
        error_message = result.get("error", "Unexpected error occurred.")
        print("Error:", error_message)
        if TK_AVAILABLE:
            messagebox.showerror("Error", error_message)

if __name__ == "__main__":
    main()
    