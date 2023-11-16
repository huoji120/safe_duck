#include "ip_blacktable.h"

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    return 0;
}
IpBlacklistDB::~IpBlacklistDB() { sqlite3_close(db); }
IpBlacklistDB::IpBlacklistDB(const std::string &dbName) {
    rc = sqlite3_open(dbName.c_str(), &db);
    if (rc) {
        LOG("Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        ERROR("sqlite3_open");
    } else {
        LOG("Opened database successfully\n");
    }
}
auto IpBlacklistDB::selectRecords() -> std::vector<IpBlacklistRecord> {
    std::vector<IpBlacklistRecord> records;
    const char *sql = "SELECT * FROM ip_black_table;";
    rc = sqlite3_exec(db, sql, selectCallback, &records, &zErrMsg);
    if (rc != SQLITE_OK) {
        ERROR("sqlite3_exec");
        sqlite3_free(zErrMsg);
    }
    return records;
}
auto IpBlacklistDB::createTable() -> void {
    const char *sql =
        "CREATE TABLE IF NOT EXISTS ip_black_table("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ip INTEGER NOT NULL,"
        "reason TEXT NOT NULL,"
        "time INTEGER NOT NULL);";

    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(zErrMsg);
    }
}
auto IpBlacklistDB::insertRecord(int ip, const std::string &reason,
                                 const uint64_t time) -> void {
    const char *sql =
        "INSERT INTO ip_black_table (ip, reason, time) VALUES (?, ?, ?);";
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    if (rc == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, ip);
        sqlite3_bind_text(stmt, 2, reason.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, time);

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            LOG("Error inserting record: %s\n", sqlite3_errmsg(db));
            ERROR("sqlite3_step");
        }
        sqlite3_finalize(stmt);
    }
}

auto IpBlacklistDB::updateRecord(int id, int ip, const std::string &reason,
                                 const uint64_t time) -> void {
    const char *sql =
        "UPDATE ip_black_table SET ip = ?, reason = ?, time = ? WHERE id = "
        "?;";
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    if (rc == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, ip);
        sqlite3_bind_text(stmt, 2, reason.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, time);
        sqlite3_bind_int(stmt, 4, id);

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            LOG("Error updating record: %s\n", sqlite3_errmsg(db));
            ERROR("sqlite3_step");
        }
        sqlite3_finalize(stmt);
    }
}

auto IpBlacklistDB::deleteRecord(int id) -> void {
    const char *sql = "DELETE FROM ip_black_table WHERE id = ?;";
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    if (rc == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, id);

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            LOG("Error delete record: %s\n", sqlite3_errmsg(db));
            ERROR("sqlite3_step");
        }
        sqlite3_finalize(stmt);
    }
}
// if time == 0 , it means forever
auto IpBlacklistDB::selectRecordByIpAndTime(uint32_t ip, uint64_t time_second)
    -> std::optional<IpBlacklistRecord> {
    std::vector<IpBlacklistRecord> records;
    int rc;

    // Get the current time and calculate the past time
    uint64_t current_time = std::time(nullptr);
    uint64_t past_time = current_time - time_second;

    // Adjusted SQL query to check if the timestamp is greater than or equal to
    // past_time
    const char *sql =
        "SELECT * FROM ip_black_table WHERE ip = ? AND (time >= ? OR time = "
        "0);";
    sqlite3_stmt *stmt;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, ip);
        sqlite3_bind_int64(stmt, 2, past_time);  // Bind the past_time parameter

        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            IpBlacklistRecord record(
                sqlite3_column_int(stmt, 0), sqlite3_column_int(stmt, 1),
                reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2)),
                sqlite3_column_int64(stmt, 3));
            records.push_back(record);
        }
        sqlite3_finalize(stmt);
    }

    if (!records.empty()) {
        return records.front();  // Assuming there's only one record for each IP
                                 // within the time range.
    } else {
        return std::nullopt;  // No record found.
    }
}
auto IpBlacklistDB::selectRecordByIp(int ip)
    -> std::optional<IpBlacklistRecord> {
    std::vector<IpBlacklistRecord> records;
    const char *sql = "SELECT * FROM ip_black_table WHERE ip = ?;";
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    if (rc == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, ip);

        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            IpBlacklistRecord record(
                sqlite3_column_int(stmt, 0), sqlite3_column_int(stmt, 1),
                reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2)),
                sqlite3_column_int64(stmt, 3));
            records.push_back(record);
        }
        sqlite3_finalize(stmt);
    }
    if (!records.empty()) {
        return records
            .front();  // Assuming there's only one record for each IP.
    } else {
        return std::nullopt;  // No record found.
    }
}
