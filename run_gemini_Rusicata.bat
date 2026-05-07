@echo off 
echo Avvio rapido per il progetto: Rusicata 
docker run -it --rm  -v "C:\Users\giova\Desktop\Rusicata:/mnt/host_context"  -v "gemini-config-data:/root/.config"  -v "gemini-auth-data:/root/.gemini"  -v "C:\Users\giova\Desktop\Rusicata:/app/output"  gemini-env 
pause 
