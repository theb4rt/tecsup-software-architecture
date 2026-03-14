from flask import Flask, request, render_template_string

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Calculadora Docker</title>
    <style>
        body { font-family: Arial; max-width: 500px; margin: 50px auto; text-align: center; }
        input { padding: 10px; margin: 5px; width: 100px; }
        button { padding: 10px 20px; background: #028090; color: white; border: none; }
    </style>
</head>
<body>
    <h1>🧮 Calculadora Dockerizada</h1>
    <form method="POST">
        <input type="number" name="num1" placeholder="Número 1" required>
        <span>+</span>
        <input type="number" name="num2" placeholder="Número 2" required>
        <button type="submit">Calcular</button>
    </form>
    {% if resultado %}
        <h2>Resultado: {{ resultado }}</h2>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def calculadora():
    resultado = None
    if request.method == 'POST':
        num1 = float(request.form['num1'])
        num2 = float(request.form['num2'])
        resultado = num1 + num2
    return render_template_string(HTML, resultado=resultado)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)