package org.tsicoop.privacyvault.framework;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.*;

public class PoolDB extends DB {

    // HikariCP DataSource instance made volatile for double-checked locking safety
    private static volatile HikariDataSource basicDataSource = null;

    // Separate initialization logic from the check
    private static synchronized void initBasicDataSource() {
        // Re-check inside synchronized block to prevent race condition
        if (basicDataSource != null) return;

        HikariConfig config = new HikariConfig();

        // Database Connection Properties
        config.setJdbcUrl(SystemConfig.getAppConfig().getProperty("framework.db.host") + "/" + SystemConfig.getAppConfig().getProperty("framework.db.name"));
        config.setUsername(SystemConfig.getAppConfig().getProperty("framework.db.user"));
        config.setPassword(SystemConfig.getAppConfig().getProperty("framework.db.password"));

        // Pool Properties
        config.setMaximumPoolSize(10);
        config.setMinimumIdle(5);
        config.setConnectionTimeout(30000);
        config.setIdleTimeout(600000);
        config.setMaxLifetime(1800000);

        // Performance Properties
        config.addDataSourceProperty("cachePrepStmts", "true");
        config.addDataSourceProperty("prepStmtCacheSize", "250");
        config.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");

        basicDataSource = new HikariDataSource(config);
        System.out.println("HikariCP DataSource initialized for PostgreSQL (Thread-Safe).");
    }

    public PoolDB() throws SQLException {
        super();
        this.con = createConnection(true);
    }

    public PoolDB(boolean autocommit) throws SQLException {
        super();
        this.con = createConnection(autocommit);
    }

    public Connection getConnection() {
        return con;
    }

    public Connection createConnection(boolean autocommit) throws SQLException {
        try {
            Class.forName("org.postgresql.Driver");
            
            // THREAD-SAFE CHECK:
            if (basicDataSource == null) {
                initBasicDataSource();
            }
            
            Connection connection = basicDataSource.getConnection();
            connection.setAutoCommit(autocommit);
            return connection;
        } catch (ClassNotFoundException e) {
            throw new SQLException("PostgreSQL Driver not found", e);
        }
    }
}