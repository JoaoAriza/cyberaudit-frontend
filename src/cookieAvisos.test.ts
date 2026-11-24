import { describe, expect, it } from "vitest";
import { avisosDoCookie } from "./cookieAvisos";

describe("avisosDoCookie com o veredito do Backend (problems)", () => {
  it("SameSite ausente mostra o aviso: o Backend grava MISSING (BUG-13)", () => {
    expect(avisosDoCookie({
      httpOnly: true, secure: true, sameSite: "MISSING", problems: ["COOKIE_SEM_SAMESITE"],
    })).toEqual(["sameSite"]);
  });

  it("token CSRF sem flags: Secure e SameSite, sem o aviso de HttpOnly", () => {
    expect(avisosDoCookie({
      httpOnly: false, secure: false, sameSite: "MISSING",
      problems: ["COOKIE_SEM_SECURE", "COOKIE_SEM_SAMESITE"],
    })).toEqual(["secure", "sameSite"]);
  });

  it("SameSite=None com Secure não é problema: sem aviso", () => {
    expect(avisosDoCookie({
      httpOnly: true, secure: true, sameSite: "None", problems: [],
    })).toEqual([]);
  });

  it("SameSite=None sem Secure: avisos de Secure e de SameSite", () => {
    expect(avisosDoCookie({
      httpOnly: true, secure: false, sameSite: "None",
      problems: ["COOKIE_SEM_SECURE", "COOKIE_SAMESITE_NONE_SEM_SECURE"],
    })).toEqual(["secure", "sameSite"]);
  });

  it("os três problemas, na ordem da tela", () => {
    expect(avisosDoCookie({
      httpOnly: false, secure: false, sameSite: "MISSING",
      problems: ["COOKIE_SEM_SECURE", "COOKIE_SEM_HTTPONLY", "COOKIE_SEM_SAMESITE"],
    })).toEqual(["httpOnly", "secure", "sameSite"]);
  });
});

describe("avisosDoCookie sem problems (scan antigo do histórico)", () => {
  it("MISSING conta como SameSite ausente", () => {
    expect(avisosDoCookie({ httpOnly: true, secure: true, sameSite: "MISSING" }))
      .toEqual(["sameSite"]);
  });

  it("SameSite=None só avisa sem Secure", () => {
    expect(avisosDoCookie({ httpOnly: true, secure: true, sameSite: "None" })).toEqual([]);
    expect(avisosDoCookie({ httpOnly: true, secure: false, sameSite: "None", problems: null }))
      .toEqual(["secure", "sameSite"]);
  });

  it("Lax e Strict não avisam; sem o campo, avisa", () => {
    expect(avisosDoCookie({ httpOnly: true, secure: true, sameSite: "Lax" })).toEqual([]);
    expect(avisosDoCookie({ httpOnly: true, secure: true, sameSite: "Strict" })).toEqual([]);
    expect(avisosDoCookie({ httpOnly: true, secure: true })).toEqual(["sameSite"]);
  });
});
