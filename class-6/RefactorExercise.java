public class RefactorExercise {
}

//EJERCICIO 1
//SRP
class Libro {
    private String titulo;
    private String autor;

    public void guardarEnArchivo() {
        // Guarda en archivo
    }

    public void imprimirEnConsola() {
        System.out.println(titulo + " - " + autor);
    }

    public void enviarPorEmail(String destinatario) {
        // Envía email
    }
}

// --- SRP Refactorizado ---

class LibroRefactored {
    private String titulo;
    private String autor;

    public LibroRefactored(String titulo, String autor) {
        this.titulo = titulo;
        this.autor = autor;
    }

    public String getTitulo() { return titulo; }
    public String getAutor() { return autor; }
}

class LibroPersistencia {
    public void guardarEnArchivo(LibroRefactored libro) {
        // Guarda en archivo
    }

class LibroPrinter {
    public void imprimirEnConsola(LibroRefactored libro) {
        System.out.println(libro.getTitulo() + " - " + libro.getAutor());
    }
}

class LibroEmailService {
    public void enviarPorEmail(LibroRefactored libro, String destinatario) {
        // Envía email
    }
}


//EJERCICIO 2
//OCP
// Extiende este sistema sin modificar la clase base:
// Agrega notificaciones por WhatsApp y Push sin modificar la clase

class Notificacion {
    public void enviar(String tipo, String mensaje) {
        if (tipo.equals("SMS")) {
            // enviar SMS
        } else if (tipo.equals("EMAIL")) {
            // enviar email
        }
    }
}

// --- OCP Refactorizado ---

interface Notificador {
    void enviar(String mensaje);
}

class SMSNotificador implements Notificador {
    public void enviar(String mensaje) {
        // enviar SMS
    }
}

class EmailNotificador implements Notificador {
    public void enviar(String mensaje) {
        // enviar email
    }
}

class WhatsAppNotificador implements Notificador {
    public void enviar(String mensaje) {
        // enviar WhatsApp
    }
}

class PushNotificador implements Notificador {
    public void enviar(String mensaje) {
        // enviar Push
    }
}


//EJERCICIO 3
//LSP
class Ave {
    public void volar() {
        Synpstem.out.println("Volando...");
    }
}

class Pinguino extends Ave {
    @Override
    public void volar() {
        throw new UnsupportedOperationException("Los pingüinos no vuelan");
    }
}

// --- LSP Refactorizado ---
// El problema: Pinguino hereda volar() pero lanza excepción,
// violando LSP porque no puede sustituir a Ave sin romper el comportamiento.

class AveBase {
    public void comer() {
        System.out.println("Comiendo...");
    }
}

class AveVoladora extends AveBase {
    public void volar() {
        System.out.println("Volando...");
    }
}

class AveNoVoladora extends AveBase {
    // No tiene volar(), no viola LSP
}

class Aguila extends AveVoladora {
    // Puede volar sin problemas
}

class PinguinoRefactored extends AveNoVoladora {
    public void nadar() {
        System.out.println("Nadando...");
    }
}

//ISP
interface Vehiculo {
    void arrancar();
    void detener();
    void volar();
    void navegar();
    void conducir();
}

//EJERCICIO 4
// --- ISP Refactorizado ---
// El problema: un Auto tendría que implementar volar() y navegar(),
// métodos que no le corresponden.

interface Arrancable {
    void arrancar();
    void detener();
}

interface Volable {
    void volar();
}

interface Navegable {
    void navegar();
}

interface Conducible {
    void conducir();
}

class Auto implements Arrancable, Conducible {
    public void arrancar() { System.out.println("Arrancando auto..."); }
    public void detener() { System.out.println("Deteniendo auto..."); }
    public void conducir() { System.out.println("Conduciendo..."); }
}

class Avion implements Arrancable, Volable {
    public void arrancar() { System.out.println("Arrancando avión..."); }
    public void detener() { System.out.println("Deteniendo avión..."); }
    public void volar() { System.out.println("Volando..."); }
}

class Barco implements Arrancable, Navegable {
    public void arrancar() { System.out.println("Arrancando barco..."); }
    public void detener() { System.out.println("Deteniendo barco..."); }
    public void navegar() { System.out.println("Navegando..."); }
}


//EJERCICIO 5
//DIP

class ReporteService {
    private PDFGenerator pdf = new PDFGenerator();

    public void generar() {
        pdf.crear();
    }
}


// Haz que pueda usar diferentes generadores (Excel, Word, etc.)

// --- DIP Refactorizado ---
// El problema: ReporteService depende directamente de PDFGenerator (clase concreta).
// Solución: depender de una abstracción e inyectar la dependencia.

interface GeneradorReporte {
    void crear();
}

class PDFGenerator implements GeneradorReporte {
    public void crear() {
        System.out.println("Generando PDF...");
    }
}

class ExcelGenerator implements GeneradorReporte {
    public void crear() {
        System.out.println("Generando Excel...");
    }
}

class WordGenerator implements GeneradorReporte {
    public void crear() {
        System.out.println("Generando Word...");

    }
}

class ReporteService {
    private GeneradorReporte generador;

    public ReporteService(GeneradorReporte generador) {
        this.generador = generador;
    }

    public void generar() {
        generador.crear();
    }
}