module.exports = {
  apps: [
    {
      name: "aegis-backend",
      script: "dist/server.cjs",
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: "1G",
      env: {
        NODE_ENV: "production",
        PORT: 3000,
      },
    },
    {
      name: "aegis-copilot",
      script: "python3",
      args: "-m copilot.server",
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: "1G",
      env: {
        PORT: 8100,
      },
    },
  ],
};
