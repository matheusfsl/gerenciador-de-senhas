package br.com.matheus.Model;

public class Credencial {

    private int id;
    private String senhaCriptografada;
    private String email;
    private String url;
    private int usuarioId;

    public Credencial() {}

    public Credencial(String email, String url, int usuarioId) {
        this.email = email;
        this.url = url;
        this.usuarioId = usuarioId;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getSenhaCriptografada() {
        return senhaCriptografada;
    }

    public void setSenhaCriptografada(String senhaCriptografada) {
        this.senhaCriptografada = senhaCriptografada;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public int getUsuarioId() {
        return usuarioId;
    }

    public void setUsuarioId(int usuarioId) {
        this.usuarioId = usuarioId;
    }
}
