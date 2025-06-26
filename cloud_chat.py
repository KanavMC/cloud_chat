# cloud_chat.py (UPDATED)

import streamlit as st
import os, json, bcrypt, time, datetime, uuid
from google.cloud import storage
from google.oauth2 import service_account

# ========= SETUP =========
CREDENTIAL_PATH = "gcs-key.json"
GCS_BUCKET = "kanav-cloud-chat-data"

credentials = service_account.Credentials.from_service_account_file(CREDENTIAL_PATH)
client = storage.Client(credentials=credentials, project=credentials.project_id)
bucket = client.bucket(GCS_BUCKET)

def gcs_file_path(filename): return f"chat_data/{filename}"
def gcs_upload(filename, data): bucket.blob(gcs_file_path(filename)).upload_from_string(json.dumps(data))
def gcs_download(filename): 
    blob = bucket.blob(gcs_file_path(filename))
    return json.loads(blob.download_as_text()) if blob.exists() else None
def gcs_delete(filename): 
    blob = bucket.blob(gcs_file_path(filename))
    if blob.exists(): blob.delete()

USERS_FILE = "users.json"
CHATS_FILE = "chats.json"
ADMINS_FILE = "admins.json"

# ========== STORAGE FUNCTIONS ==========
def load_users(): return gcs_download(USERS_FILE) or {}
def save_users(users): gcs_upload(USERS_FILE, users)

def load_chats(): return gcs_download(CHATS_FILE) or {}
def save_chats(chats): gcs_upload(CHATS_FILE, chats)

def register_user(username, password):
    users = load_users()
    if username in users: return False
    users[username] = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    save_users(users)
    return True

def login_user(username, password):
    users = load_users()
    return username in users and bcrypt.checkpw(password.encode(), users[username].encode())

def chat_filename(chat_id): return f"chat_{chat_id}.json"
def load_messages(chat_id):
    data = gcs_download(chat_filename(chat_id)) or []
    return [msg for msg in data if time.time() - msg["timestamp"] < 3600]
def save_messages(chat_id, messages): gcs_upload(chat_filename(chat_id), messages)

# ========== THEMES ==========
themes = {
    "Ocean": {"bg": "#E0F7FA", "text": "#006064"},
    "Dark": {"bg": "#212121", "text": "#FFFFFF"},
    "White": {"bg": "#FFFFFF", "text": "#000000"},
    "Sunset": {"bg": "#FFECB3", "text": "#E65100"},
    "Forest": {"bg": "#E8F5E9", "text": "#1B5E20"},
    "Bubblegum": {"bg": "#F8BBD0", "text": "#880E4F"},
    "Neon": {"bg": "#1a1a40", "text": "#39ff14"},
    "Steel": {"bg": "#cfd8dc", "text": "#263238"},
    "Candy": {"bg": "#fff0f5", "text": "#ff1493"},
}

# ========== SESSION STATE ==========
st.set_page_config(page_title="Cloud Chat ☁️", layout="centered")

if "logged_in" not in st.session_state: st.session_state.logged_in = False
if "username" not in st.session_state: st.session_state.username = ""
if "theme" not in st.session_state: st.session_state.theme = "Ocean"

# ========== LOGIN / REGISTER ==========
if not st.session_state.logged_in:
    login_tab, reg_tab = st.tabs(["🔐 Login", "📝 Register"])
    with login_tab:
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Login") and login_user(u, p):
            st.session_state.logged_in = True
            st.session_state.username = u
            st.rerun()
    with reg_tab:
        u = st.text_input("New Username")
        p = st.text_input("New Password", type="password")
        if st.button("Register"):
            if register_user(u, p):
                st.success("Registered! Please login.")
            else:
                st.error("Username exists.")
else:
    chats = load_chats()
    users = load_users()
    admins = gcs_download(ADMINS_FILE) or ["KanavBhowmick"]
    is_admin = st.session_state.username in admins

    st.session_state.theme = st.sidebar.selectbox("🎨 Theme", list(themes), index=list(themes).index(st.session_state.theme))
    theme = themes[st.session_state.theme]

    st.markdown(f"""
    <style>
    .stApp {{ background-color: {theme['bg']}; color: {theme['text']} }}
    label, .stText, .stMarkdown p {{ color: {theme['text']} !important }}
    </style>
    <audio autoplay loop>
        <source src="https://www.bensound.com/bensound-music/bensound-goinghigher.mp3" type="audio/mpeg">
    </audio>
    """, unsafe_allow_html=True)

    st.markdown(f"<h2 style='color:{theme['text']}'>☁️ Kanav Inc Cloud Chat</h2>", unsafe_allow_html=True)

    if "general" not in chats:
        chats["general"] = {"name": "General Chat", "owner": "admin", "private": False, "members": [], "key": "public01"}
        save_chats(chats)

    st.markdown("### 🌍 Public Chats")
    public_ids = [cid for cid, c in chats.items() if not c["private"]]
    public_lookup = {cid: chats[cid]["name"] for cid in public_ids}
    selected_pub = st.selectbox("Join a public chat:", ["-- Select Chat --"] + list(public_lookup.values()))
    if selected_pub != "-- Select Chat --":
        for cid, cname in public_lookup.items():
            if cname == selected_pub and st.session_state.username not in chats[cid]["members"]:
                chats[cid]["members"].append(st.session_state.username)
                save_chats(chats)
                st.success(f"Joined {cname}")
                st.rerun()

    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        name = st.text_input("New Chat Name")
        priv = st.checkbox("Private Chat")
        if st.button("Create Chat"):
            owned = [c for c in chats.values() if c["owner"] == st.session_state.username]
            if len(owned) >= 3 and not is_admin:
                st.error("Limit 3 chats.")
            else:
                cid = str(uuid.uuid4())[:8]
                chats[cid] = {"name": name, "owner": st.session_state.username, "private": priv, "members": [st.session_state.username], "key": str(uuid.uuid4())[:6]}
                save_chats(chats)
                st.success("Chat created.")
                st.rerun()

    with col2:
        join = st.text_input("Enter Join Key")
        if st.button("Join Chat"):
            for cid, c in chats.items():
                if c["key"] == join:
                    if st.session_state.username not in c["members"]:
                        c["members"].append(st.session_state.username)
                        save_chats(chats)
                        st.success(f"Joined {c['name']}")
                        st.rerun()

    user_chats = [cid for cid, c in chats.items() if st.session_state.username in c["members"]]
    selected_chat = st.selectbox("📂 Your Chats", user_chats, format_func=lambda x: chats[x]["name"])

    if selected_chat:
        chat = chats[selected_chat]
        st.markdown(f"**Chat Name:** {chat['name']}")
        st.markdown(f"**Join Key:** `{chat['key']}`")
        st.markdown(f"### 👥 Chat Members: {', '.join(chat['members'])}")
        if st.button("Leave Chat"):
            chat['members'].remove(st.session_state.username)
            save_chats(chats)
            st.rerun()

        messages = load_messages(selected_chat)
        for m in messages:
            t = datetime.datetime.fromtimestamp(m["timestamp"]).strftime("%H:%M")
            u = m["user"]
            st.markdown(f"<p style='color:{theme['text']};'><b>{u}</b> <i style='font-size:smaller'>({t})</i>: {m['text']}</p>", unsafe_allow_html=True)

        with st.form("send_msg"):
            msg = st.text_input("Message", max_chars=300)
            if st.form_submit_button("Send") and msg.strip():
                messages.append({"user": st.session_state.username, "text": msg.strip(), "timestamp": time.time()})
                save_messages(selected_chat, messages)
                st.rerun()

        if chat["owner"] == st.session_state.username:
            with st.expander("⚙️ Manage This Chat"):
                promote = st.text_input("Promote member to new owner")
                if st.button("Promote To Owner") and promote in chat["members"]:
                    chat["owner"] = promote
                    save_chats(chats)
                    st.success(f"{promote} is now the owner!")
                    st.rerun()
                if st.button("❌ Delete This Chat"):
                    gcs_delete(chat_filename(selected_chat))
                    del chats[selected_chat]
                    save_chats(chats)
                    st.rerun()
                kick = st.text_input("Kick a user from this chat")
                if st.button("Kick User"):
                    if kick in chat["members"]:
                        chat["members"].remove(kick)
                        save_chats(chats)
                        st.success(f"Kicked {kick}")
                        st.rerun()

    if is_admin:
        st.markdown("---")
        if st.button("🧹 Delete ALL messages in ALL chats"):
            for cid in chats:
                gcs_delete(chat_filename(cid))
            st.rerun()
        promote_user = st.text_input("Make someone admin (type their username):")
        if st.button("Promote to Admin"):
            users = load_users()
            if promote_user in users:
                admins = gcs_download(ADMINS_FILE) or []
                if promote_user not in admins:
                    admins.append(promote_user)
                    gcs_upload(ADMINS_FILE, admins)
                    st.success(f"{promote_user} is now an admin!")
                else:
                    st.warning("Already an admin")
            else:
                st.error("User not found")

    if not is_admin:
        owned_chats = [c for c in chats.values() if c['owner'] == st.session_state.username]
        remaining = 3 - len(owned_chats)
        st.sidebar.info(f"You can create {remaining} more chat(s)")

    if st.button("Log Out"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.rerun()
