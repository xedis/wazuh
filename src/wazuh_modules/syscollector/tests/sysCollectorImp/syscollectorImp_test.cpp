/*
 * Wazuh SyscollectorImp
 * Copyright (C) 2015-2020, Wazuh Inc.
 * November 9, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "syscollectorImp_test.h"
#include "syscollector.hpp"

void SyscollectorImpTest::SetUp() {};

void SyscollectorImpTest::TearDown()
{
};

using ::testing::_;
using ::testing::Return;

class SysInfoWrapper: public ISysInfo
{
public:
    SysInfoWrapper() = default;
    ~SysInfoWrapper() = default;
    MOCK_METHOD(nlohmann::json, hardware, (), (override));
    MOCK_METHOD(nlohmann::json, packages, (), (override));
    MOCK_METHOD(nlohmann::json, os, (), (override));    
    MOCK_METHOD(nlohmann::json, networks, (), (override));    
    MOCK_METHOD(nlohmann::json, processes, (), (override));
    MOCK_METHOD(nlohmann::json, ports, (), (override));
};

TEST_F(SyscollectorImpTest, defaultCtor)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(R"({"board_serial":"Intel Corporation","cpu_MHz":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","ram_free":2257872,"ram_total":4972208,"ram_usage":54})")));
    EXPECT_CALL(*spInfoWrapper, packages()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"name":"TEXT", "version":"TEXT", "vendor":"TEXT", "install_time":"TEXT", "location":"TEXT", "architecture":"TEXT", "groups":"TEXT", "description":"TEXT", "size":"TEXT", "priority":"TEXT", "multiarch":"TEXT", "source":"TEXT"}])")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(R"({"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0}])")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));
    Syscollector syscollector{spInfoWrapper, "5s"};
}

TEST_F(SyscollectorImpTest, intervalSeconds)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return(nlohmann::json::parse(R"({"board_serial":"Intel Corporation","cpu_MHz":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","ram_free":2257872,"ram_total":4972208,"ram_usage":54})")));
    EXPECT_CALL(*spInfoWrapper, packages()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"architecture":"amd64","group":"x11","name":"xserver-xorg","priority":"optional","size":"411","source":"xorg","version":"1:7.7+19ubuntu14"}])")));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return(nlohmann::json::parse(R"({"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0}])")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    Syscollector syscollector{spInfoWrapper, "100s"};
}

TEST_F(SyscollectorImpTest, intervalMinutes)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return(nlohmann::json::parse(R"({"board_serial":"Intel Corporation","cpu_MHz":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","ram_free":2257872,"ram_total":4972208,"ram_usage":54})")));
    EXPECT_CALL(*spInfoWrapper, packages()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"architecture":"amd64","group":"x11","name":"xserver-xorg","priority":"optional","size":"411","source":"xorg","version":"1:7.7+19ubuntu14"}])")));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return(nlohmann::json::parse(R"({"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0}])")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    Syscollector syscollector{spInfoWrapper, "100m"};
}

TEST_F(SyscollectorImpTest, intervalDays)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return(nlohmann::json::parse(R"({"board_serial":"Intel Corporation","cpu_MHz":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","ram_free":2257872,"ram_total":4972208,"ram_usage":54})")));
    EXPECT_CALL(*spInfoWrapper, packages()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"architecture":"amd64","group":"x11","name":"xserver-xorg","priority":"optional","size":"411","source":"xorg","version":"1:7.7+19ubuntu14"}])")));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return(nlohmann::json::parse(R"({"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0}])")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    Syscollector syscollector{spInfoWrapper, "1d"};
}

TEST_F(SyscollectorImpTest, intervalUnknownUnit)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return(nlohmann::json::parse(R"({"board_serial":"Intel Corporation","cpu_MHz":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","ram_free":2257872,"ram_total":4972208,"ram_usage":54})")));
    EXPECT_CALL(*spInfoWrapper, packages()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"architecture":"amd64","group":"x11","name":"xserver-xorg","priority":"optional","size":"411","source":"xorg","version":"1:7.7+19ubuntu14"}])")));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return(nlohmann::json::parse(R"({"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0}])")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    Syscollector syscollector{spInfoWrapper, "1y"};
}

TEST_F(SyscollectorImpTest, noScanOnStart)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, packages()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);
    EXPECT_CALL(*spInfoWrapper, networks()).Times(0);
    EXPECT_CALL(*spInfoWrapper, processes()).Times(0);
    EXPECT_CALL(*spInfoWrapper, ports()).Times(0);
    Syscollector syscollector{spInfoWrapper, "1h", false};
}

TEST_F(SyscollectorImpTest, noHardware)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, packages()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"architecture":"amd64","group":"x11","name":"xserver-xorg","priority":"optional","size":"411","source":"xorg","version":"1:7.7+19ubuntu14"}])")));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return(nlohmann::json::parse(R"({"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0}])")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    Syscollector syscollector{spInfoWrapper, "1h", true, false};
}

TEST_F(SyscollectorImpTest, noOs)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return(nlohmann::json::parse(R"({"board_serial":"Intel Corporation","cpu_MHz":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","ram_free":2257872,"ram_total":4972208,"ram_usage":54})")));
    EXPECT_CALL(*spInfoWrapper, packages()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"architecture":"amd64","group":"x11","name":"xserver-xorg","priority":"optional","size":"411","source":"xorg","version":"1:7.7+19ubuntu14"}])")));
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0}])")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    Syscollector syscollector{spInfoWrapper, "1h", true, true, false};
}

TEST_F(SyscollectorImpTest, noNetwork)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return(nlohmann::json::parse(R"({"board_serial":"Intel Corporation","cpu_MHz":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","ram_free":2257872,"ram_total":4972208,"ram_usage":54})")));
    EXPECT_CALL(*spInfoWrapper, packages()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"architecture":"amd64","group":"x11","name":"xserver-xorg","priority":"optional","size":"411","source":"xorg","version":"1:7.7+19ubuntu14"}])")));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return(nlohmann::json::parse(R"({"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).Times(0);
    EXPECT_CALL(*spInfoWrapper, processes()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0}])")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    Syscollector syscollector{spInfoWrapper, "1h", true, true, true, false};
}

TEST_F(SyscollectorImpTest, noPackages)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return(nlohmann::json::parse(R"({"board_serial":"Intel Corporation","cpu_MHz":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","ram_free":2257872,"ram_total":4972208,"ram_usage":54})")));
    EXPECT_CALL(*spInfoWrapper, packages()).Times(0);
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return(nlohmann::json::parse(R"({"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, processes()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0}])")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    Syscollector syscollector{spInfoWrapper, "1h", true, true, true, true, false};
}

TEST_F(SyscollectorImpTest, noPorts)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return(nlohmann::json::parse(R"({"board_serial":"Intel Corporation","cpu_MHz":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","ram_free":2257872,"ram_total":4972208,"ram_usage":54})")));
    EXPECT_CALL(*spInfoWrapper, packages()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"architecture":"amd64","group":"x11","name":"xserver-xorg","priority":"optional","size":"411","source":"xorg","version":"1:7.7+19ubuntu14"}])")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return(nlohmann::json::parse(R"({"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, processes()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0}])")));
    EXPECT_CALL(*spInfoWrapper, ports()).Times(0);   
    Syscollector syscollector{spInfoWrapper, "1h", true, true, true, true, true, false};
}

TEST_F(SyscollectorImpTest, noPortsAll)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return(nlohmann::json::parse(R"({"board_serial":"Intel Corporation","cpu_MHz":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","ram_free":2257872,"ram_total":4972208,"ram_usage":54})")));
    EXPECT_CALL(*spInfoWrapper, packages()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"architecture":"amd64","group":"x11","name":"xserver-xorg","priority":"optional","size":"411","source":"xorg","version":"1:7.7+19ubuntu14"}])")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return(nlohmann::json::parse(R"({"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, processes()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0}])")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    Syscollector syscollector{spInfoWrapper, "1h", true, true, true, true, true, true, false};
}

TEST_F(SyscollectorImpTest, noProcesses)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return(nlohmann::json::parse(R"({"board_serial":"Intel Corporation","cpu_MHz":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","ram_free":2257872,"ram_total":4972208,"ram_usage":54})")));
    EXPECT_CALL(*spInfoWrapper, packages()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"architecture":"amd64","group":"x11","name":"xserver-xorg","priority":"optional","size":"411","source":"xorg","version":"1:7.7+19ubuntu14"}])")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return(nlohmann::json::parse(R"({"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, processes()).Times(0);
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));
    Syscollector syscollector{spInfoWrapper, "1h", true, true, true, true, true, true, true, false};
}

TEST_F(SyscollectorImpTest, noHotfixes)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return(nlohmann::json::parse(R"({"board_serial":"Intel Corporation","cpu_MHz":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","ram_free":2257872,"ram_total":4972208,"ram_usage":54})")));
    EXPECT_CALL(*spInfoWrapper, packages()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"architecture":"amd64","group":"x11","name":"xserver-xorg","priority":"optional","size":"411","source":"xorg","version":"1:7.7+19ubuntu14"}])")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return(nlohmann::json::parse(R"({"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, processes()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0}])")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    Syscollector syscollector{spInfoWrapper, "1h", true, true, true, true, true, true, true, true, false};
}

TEST_F(SyscollectorImpTest, scanOnInverval)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(R"({"board_serial":"Intel Corporation","cpu_MHz":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","ram_free":2257872,"ram_total":4972208,"ram_usage":54})")));
    EXPECT_CALL(*spInfoWrapper, packages()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"architecture":"amd64","group":"x11","name":"xserver-xorg","priority":"optional","size":"411","source":"xorg","version":"1:7.7+19ubuntu14"}])")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(R"({"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, processes()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0}])")));
    EXPECT_CALL(*spInfoWrapper, processes()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":20,"vm_size":0}])")));
    EXPECT_CALL(*spInfoWrapper, processes()).WillRepeatedly(Return(nlohmann::json::parse(R"([{"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":20,"vm_size":0}])")));
    EXPECT_CALL(*spInfoWrapper, processes()).WillRepeatedly(Return(nlohmann::json::parse(R"({"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":20,"vm_size":0})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return("ports"));    
    Syscollector syscollector{spInfoWrapper, "1s"};
    std::this_thread::sleep_for(std::chrono::seconds{5});
}