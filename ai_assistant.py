"""
Assistant IA (WhiteHat-AI) — Gemini.

Ce module est ISOLÉ du reste du client volontairement, pour deux raisons :

1. Ce n'est PAS une fonctionnalité demandée par l'énoncé UE14. C'est un bonus
   ajouté pour se démarquer. Le garder dans son propre fichier permet de
   l'expliquer facilement en défense ("c'est ici, et seulement ici") et de le
   désactiver en une ligne si besoin (AI_ENABLED = False juste en dessous).

2. Vulnérabilité identifiée en cours (remarque du prof) : Secsy Chat est un
   système de chiffrement de bout en bout. Dès qu'un message est envoyé à
   l'IA, il sort de ce périmètre : il part en clair vers les serveurs de
   Google, hors de tout ce que le projet met en place pour protéger les
   échanges. Ce n'est pas corrigeable "techniquement" (on ne peut pas
   chiffrer de bout en bout un appel à une IA externe qui doit lire le texte
   en clair pour y répondre) — donc on gère le risque autrement :
     - l'utilisateur est prévenu AVANT l'envoi (voir AI_WARNING, affiché par
       client.py avant le premier appel de la session) ;
     - seul le message explicitement adressé à l'IA part vers Google, jamais
       tout l'historique du canal ni les messages d'autres utilisateurs ;
     - les fichiers ne sont envoyés que si l'utilisateur les a explicitement
       donnés à l'IA (/ia pro <fichiers>), jamais automatiquement.
"""

import os
import logging

logger = logging.getLogger("Client")

# Pour désactiver complètement l'assistant IA (ex. pour une version "cours
# cybersécurité" du projet où on ne veut aucun appel réseau externe) :
# mettre AI_ENABLED = False. Rien d'autre à changer.
AI_ENABLED = True

AI_WARNING = "⚠️ Ce qui est envoyé à l'IA part en clair chez Google (hors chiffrement). Rien de confidentiel."
AI_DISABLED_REASON = "désactivée (AI_ENABLED = False dans ai_assistant.py)."
# Extensions de fichiers que /ia2 refuse d'envoyer (clés RSA, clé Gemini, base de données, logs)
SENSITIVE_EXT = (".key", ".pem", ".db", ".log")


def _load_api_key() -> str:
    """La clé n'est JAMAIS écrite dans le code. Elle vient, dans l'ordre :
    1. de la variable d'environnement GEMINI_API_KEY ;
    2. du fichier gemini.key à côté du client (ignoré par git, comme tous les *.key).
    Clé gratuite : https://aistudio.google.com/api-keys"""
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not key and os.path.exists("gemini.key"):
        key = open("gemini.key", encoding="utf-8").read().strip()
    return key


_client = None
if AI_ENABLED:
    try:
        import google.genai as genai
        _key = _load_api_key()
        if not _key:
            AI_DISABLED_REASON = "aucune clé. Mets-la dans le fichier gemini.key ou dans GEMINI_API_KEY."
            raise RuntimeError("clé Gemini absente")
        _client = genai.Client(api_key=_key)
    except ImportError:
        AI_DISABLED_REASON = "paquet google-genai absent (pip install -r requirements.txt)."
    except Exception as e:
        if AI_DISABLED_REASON.startswith("désactivée"):
            AI_DISABLED_REASON = f"erreur au démarrage ({e})."
    if _client is None:
        logger.warning(f"Assistant IA indisponible : {AI_DISABLED_REASON}")
        AI_ENABLED = False


# Modèles essayés dans l'ordre : Google réserve les modèles 2.5 aux comptes qui les utilisaient
# déjà, une nouvelle clé doit donc passer par les modèles récents.
MODELS = {
    "normal": ["gemini-3.8-flash", "gemini-2.5-flash"],
    "pro":    ["gemini-3.1-pro-preview", "gemini-2.5-pro", "gemini-3.8-flash"],
}


def _generate(models: list, contents: list):
    """Essaie chaque modèle ; passe au suivant seulement si celui-ci est introuvable ou non autorisé."""
    for i, model_name in enumerate(models):
        try:
            return _client.models.generate_content(model=model_name, contents=contents)
        except Exception as e:
            err = str(e).lower()
            unavailable = any(w in err for w in ("404", "not found", "not_found", "permission", "403"))
            if not unavailable or i == len(models) - 1:
                raise
            logger.warning(f"Modèle {model_name} indisponible, essai du suivant")


def ask_ai(question: str = "", fichiers: list = None, mode: str = "normal") -> str:
    """mode = normal (Flash) ou pro. Ne renvoie QUE le texte de réponse (ou un message d'erreur)."""
    if not AI_ENABLED or _client is None:
        return f"❌ IA indisponible : {AI_DISABLED_REASON}"

    try:

        # La TUI affiche du texte brut : pas de Markdown, et des réponses courtes pour un chat
        format_rules = ("Réponds en français, en texte brut : pas de Markdown (ni astérisques, ni #, "
                        "ni tableaux). Va droit au but. Utilise des tirets simples pour une liste.")
        system_prompt = (
            "Tu es WhiteHat-AI Pro, un expert précis et rigoureux. Réponse structurée, 15 lignes maximum. "
            + format_rules
        ) if mode == "pro" else (
            "Tu es WhiteHat-AI, un assistant de messagerie sympa et compétent. Réponse courte, 6 lignes maximum. "
            + format_rules
        )

        contents = [system_prompt]

        if fichiers:
            file_contents = []
            total_chars = 0
            for fichier in fichiers:
                try:
                    if not os.path.exists(fichier):
                        file_contents.append(f"--- FICHIER : {fichier} ---\n[Erreur : Fichier introuvable]")
                        continue
                    if fichier.lower().endswith(SENSITIVE_EXT):
                        # Clés privées, base de données... : ne partent JAMAIS chez Google, même sur demande
                        file_contents.append(f"--- FICHIER : {fichier} ---\n[Refusé : fichier sensible]")
                        continue

                    ext = fichier.lower()

                    if ext.endswith('.pdf'):
                        try:
                            from pypdf import PdfReader
                            reader = PdfReader(fichier)
                            content = "\n".join([page.extract_text() or "" for page in reader.pages])
                        except ImportError:
                            content = "[ERREUR : Module pypdf non installé → pip install pypdf]"
                        except Exception as e:
                            content = f"[ERREUR lecture PDF : {str(e)}]"

                    elif ext.endswith('.docx'):
                        try:
                            from docx import Document
                            doc = Document(fichier)
                            content = "\n".join([paragraph.text for paragraph in doc.paragraphs if paragraph.text.strip()])
                        except ImportError:
                            content = "[ERREUR : Module python-docx non installé → pip install python-docx]"
                        except Exception as e:
                            content = f"[ERREUR lecture DOCX : {str(e)}]"

                    else:
                        with open(fichier, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                    total_chars += len(content)
                    if total_chars > 40000:
                        file_contents.append(f"--- FICHIER : {fichier} ---\n[Trop volumineux]")
                        break

                    file_contents.append(f"--- FICHIER : {fichier} ---\n{content}\n")

                except Exception as e:
                    file_contents.append(f"--- ERREUR {fichier} : {str(e)}")

            contents.append("Fichiers fournis (contenu extrait) :\n" + "\n".join(file_contents))
            if question:
                contents.append(f"Question utilisateur : {question}")
            else:
                contents.append("Analyse ces documents en détail.")
        elif question:
            contents.append(question)
        else:
            contents.append("Bonjour")

        response = _generate(MODELS["pro" if mode == "pro" else "normal"], contents)
        # Filet de sécurité si le modèle met quand même du Markdown
        return response.text.replace("**", "").replace("__", "").strip()

    except Exception as e:
        error_str = str(e).lower()

        if "429" in error_str or "quota" in error_str or "rate limit" in error_str or "too many requests" in error_str:
            if mode == "pro":
                logger.warning("Rate limit Pro atteint → fallback sur Flash")
                return ask_ai(question=question, fichiers=fichiers, mode="normal")
            return "❌ Rate limit Gemini atteint (429). Attends 30-60 secondes et réessaie."

        if "500" in error_str or "internal" in error_str or "unavailable" in error_str or "503" in error_str:
            logger.error(f"Erreur serveur Gemini ({mode}) : {e}")
            return "❌ Le service Gemini est momentanément indisponible (erreur serveur). Réessaie dans quelques instants."

        logger.error(f"Erreur Gemini ({mode}) : {e}")
        return f"❌ Erreur IA ({mode}) : {e}"
