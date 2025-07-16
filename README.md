# Connect App: Backend & React Native Frontend

## Backend (FastAPI)

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Run the server:**
   ```bash
   uvicorn main:app --reload --port 8000
   ```
- All data is stored in `data.json` in this directory.
- Main endpoints: `/users`, `/chats`, `/stories`, `/search`, `/settings`, `/add-up`, `/groups`, `/auth/*`, `/ws/chat/{chat_id}` (WebSocket)
- Test endpoints using Postman, curl, or the React Native frontend.

---

## Frontend (React Native)

### First Steps

1. **Initialize the React Native project (using Expo recommended):**
   ```bash
   npx create-expo-app frontend
   cd frontend
   npm install
   ```
2. **Set up navigation (bottom tabs):**
   ```bash
   npm install @react-navigation/native @react-navigation/bottom-tabs react-native-screens react-native-safe-area-context
   npx expo install react-native-gesture-handler react-native-reanimated
   ```
3. **Create API service for backend communication:**
   - Create `/src/api/index.js` to handle all HTTP requests to the FastAPI backend.
4. **Implement authentication screens:**
   - Create `/src/screens/LoginScreen.js`, `/src/screens/RegisterScreen.js`, and social login if needed.
5. **Scaffold main tabs/screens:**
   - `/src/screens/ChatsScreen.js`
   - `/src/screens/GroupsScreen.js`
   - `/src/screens/StoriesScreen.js`
   - `/src/screens/SearchScreen.js`
   - `/src/screens/SettingsScreen.js`

### To run the frontend:
```bash
cd frontend
npx expo start
```

---

## Running Both Together
- Start the backend server (`uvicorn ...`) and the frontend (`npx expo start`) in separate terminals.
- Make sure the frontend API service points to your backend URL (e.g., `http://127.0.0.1:8000`).

---

## .gitignore
- Add a `.gitignore` file to exclude environment files, Python cache, and node_modules:
```
# Python
__pycache__/
*.pyc
.env

# Node/React Native
node_modules/
.expo/
.expo-shared/
``` 