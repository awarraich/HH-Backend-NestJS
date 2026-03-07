module.exports = {
  apps: [
    {
      name: 'hh-backend',
      script: 'dist/main.js',
      instances: 1,
      exec_mode: 'fork',
      env: {
        NODE_ENV: 'production',
        PORT: 3000,
      },
      // Logging
      error_file: './logs/pm2-error.log',
      out_file: './logs/pm2-out.log',
      log_file: './logs/pm2-combined.log',
      time: true,
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true,
      
      // Auto restart
      autorestart: true,
      watch: false,
      max_memory_restart: '500M',
      
      // Graceful shutdown
      kill_timeout: 5000,
      wait_ready: true,
      listen_timeout: 10000,
      
      // Advanced PM2 features
      min_uptime: '10s',
      max_restarts: 10,
      restart_delay: 4000,
      
      // Source map support
      source_map_support: true,
      
      // Environment variables (will be overridden by .env file)
      env_production: {
        NODE_ENV: 'production',
      },
    },
  ],
};

