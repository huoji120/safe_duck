#pragma once
#include "head.h"
struct IpBlacklistRecord {
    int id;
    int ip;
    std::string reason;
    uint64_t time;

    IpBlacklistRecord(int id, int ip, std::string reason, uint64_t time)
        : id(id), ip(ip), reason(std::move(reason)), time(std::move(time)) {}
};
class IpBlacklistDB {
   private:
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;

   public:
    IpBlacklistDB(const std::string &dbName);

    ~IpBlacklistDB();

    auto createTable() -> void;

    auto insertRecord(int ip, const std::string &reason, const uint64_t time)
        -> void;

    auto updateRecord(int id, int ip, const std::string &reason,
                      const uint64_t time) -> void;

    auto deleteRecord(int id) -> void;

    auto selectRecordByIpAndTime(uint32_t ip, uint64_t time_second)
        -> std::optional<IpBlacklistRecord>;

    static int selectCallback(void *data, int argc, char **argv,
                              char **azColName) {
        auto *records = static_cast<std::vector<IpBlacklistRecord> *>(data);
        records->emplace_back(std::stoi(argv[0]),      // id
                              std::stoi(argv[1]),      // ip
                              argv[2] ? argv[2] : "",  // reason
                              std::stold(argv[3])      // time
        );
        return 0;
    }
    auto selectRecordByIp(int ip) -> std::optional<IpBlacklistRecord>;
    auto selectRecords() -> std::vector<IpBlacklistRecord>;
};
