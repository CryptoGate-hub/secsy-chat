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

AI_WARNING = (
    "⚠️  Un message envoyé à l'IA (WhiteHat-AI) part en clair vers les serveurs "
    "de Google (Gemini) et sort donc du chiffrement de bout en bout de Secsy Chat. "
    "N'y mets rien de confidentiel."
)

try:
    import google.genai as genai
    # La clé n'est JAMAIS écrite dans le code : elle vient de la variable d'environnement GEMINI_API_KEY
    # (PowerShell : $env:GEMINI_API_KEY = "ta_clé" ; clé gratuite : https://aistudio.google.com/api-keys)
    _client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
except Exception as e:  # SDK absent, variable GEMINI_API_KEY absente, etc. → on désactive proprement
    logger.warning(f"Assistant IA indisponible ({e}) — fonctionnalité désactivée")
    AI_ENABLED = False
    _client = None


def ask_ai(question: str = "", fichiers: list = None, mode: str = "normal") -> str:
    """mode = normal (Flash) ou pro. Ne renvoie QUE le texte de réponse (ou un message d'erreur)."""
    if not AI_ENABLED or _client is None:
        return "❌ Assistant IA désactivé sur ce client."

    try:
        model_name = "gemini-2.5-pro" if mode == "pro" else "gemini-2.5-flash"

        system_prompt = (
            "Tu es WhiteHat-AI 2.0 Pro, une IA experte, très précise, créative et rigoureuse. "
            "Réponds de façon détaillée, structurée et professionnelle en français."
        ) if mode == "pro" else (
            "Tu es WhiteHat-AI, un assistant IA intelligent, sympa, créatif et très compétent. "
            "Réponds en français de façon claire, structurée et utile."
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

        response = _client.models.generate_content(model=model_name, contents=contents)
        return response.text.strip()

    except Exception as e:
        error_str = str(e).lower()

        if "429" in error_str or "quota" in error_str or "rate limit" in error_str or "too many requests" in error_str:
            if mode == "pro":
                logger.warning("Rate limit Pro atteint → fallback sur Flash")
                return ask_ai(question=question, fichiers=fichiers, mode="normal")
            return "❌ **Rate limit Gemini atteint** (429). Attends 30-60 secondes et réessaie."

        if "500" in error_str or "internal" in error_str or "unavailable" in error_str or "503" in error_str:
            logger.error(f"Erreur serveur Gemini ({mode}) : {e}")
            return "❌ Le service Gemini est momentanément indisponible (erreur serveur). Réessaie dans quelques instants."

        logger.error(f"Erreur Gemini ({mode}) : {e}")
        return f"❌ Erreur IA ({mode}) : {e}"
