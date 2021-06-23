package main

import (
	"database/sql"
	"encoding/json"
)

type systemMetrics struct {
	Domains []struct {
		UUID                     string      `json:"UUID"`
		CPUCores                 int64       `json:"cpu_cores"`
		CPUOtherSteal            int64       `json:"cpu_other_steal"`
		CPUOtherTotal            int64       `json:"cpu_other_total"`
		CPUSteal                 int64       `json:"cpu_steal"`
		CPUTotal                 int64       `json:"cpu_total"`
		DiskDelayblkio           json.Number `json:"disk_delayblkio"`
		DiskSizeAllocation       int64       `json:"disk_size_allocation"`
		DiskSizeCapacity         int64       `json:"disk_size_capacity"`
		DiskSizePhysical         int64       `json:"disk_size_physical"`
		DiskStatsFlushreq        int64       `json:"disk_stats_flushreq"`
		DiskStatsFlushtotaltimes int64       `json:"disk_stats_flushtotaltimes"`
		DiskStatsRdbytes         int64       `json:"disk_stats_rdbytes"`
		DiskStatsRdreq           int64       `json:"disk_stats_rdreq"`
		DiskStatsRdtotaltimes    int64       `json:"disk_stats_rdtotaltimes"`
		DiskStatsWrbytes         int64       `json:"disk_stats_wrbytes"`
		DiskStatsWrreq           int64       `json:"disk_stats_wrreq"`
		DiskStatsWrtotaltimes    int64       `json:"disk_stats_wrtotaltimes"`
		HostName                 string      `json:"host_name"`
		IoCancelledWriteBytes    int64       `json:"io_cancelled_write_bytes"`
		IoRchar                  int64       `json:"io_rchar"`
		IoReadBytes              json.Number `json:"io_read_bytes"`
		IoSyscr                  int64       `json:"io_syscr"`
		IoSyscw                  int64       `json:"io_syscw"`
		IoWchar                  int64       `json:"io_wchar"`
		IoWriteBytes             int64       `json:"io_write_bytes"`
		Name                     string      `json:"name"`
		NetInterfaces            string      `json:"net_interfaces"`
		NetReceivedBytes         json.Number `json:"net_receivedBytes"`
		NetReceivedCompressed    int64       `json:"net_receivedCompressed"`
		NetReceivedDrop          int64       `json:"net_receivedDrop"`
		NetReceivedErrs          int64       `json:"net_receivedErrs"`
		NetReceivedFifo          int64       `json:"net_receivedFifo"`
		NetReceivedFrame         int64       `json:"net_receivedFrame"`
		NetReceivedMulticast     int64       `json:"net_receivedMulticast"`
		NetReceivedPackets       int64       `json:"net_receivedPackets"`
		NetTransmittedBytes      int64       `json:"net_transmittedBytes"`
		NetTransmittedCarrier    int64       `json:"net_transmittedCarrier"`
		NetTransmittedColls      int64       `json:"net_transmittedColls"`
		NetTransmittedCompressed int64       `json:"net_transmittedCompressed"`
		NetTransmittedDrop       int64       `json:"net_transmittedDrop"`
		NetTransmittedErrs       int64       `json:"net_transmittedErrs"`
		NetTransmittedFifo       int64       `json:"net_transmittedFifo"`
		NetTransmittedPackets    int64       `json:"net_transmittedPackets"`
		RAMCmajflt               float64     `json:"ram_cmajflt"`
		RAMCminflt               float64     `json:"ram_cminflt"`
		RAMMajflt                float64     `json:"ram_majflt"`
		RAMMinflt                json.Number `json:"ram_minflt"`
		RAMRss                   int64       `json:"ram_rss"`
		RAMTotal                 int64       `json:"ram_total"`
		RAMUsed                  int64       `json:"ram_used"`
		RAMVsize                 int64       `json:"ram_vsize"`
	} `json:"domains"`
	Host struct {
		CPUCores                     int64       `json:"cpu_cores"`
		CPUCurfreq                   float64     `json:"cpu_curfreq"`
		CPUMaxfreq                   float64     `json:"cpu_maxfreq"`
		CPUMinfreq                   float64     `json:"cpu_minfreq"`
		DiskDeviceCurrentops         float64     `json:"disk_device_currentops"`
		DiskDeviceReads              int64       `json:"disk_device_reads"`
		DiskDeviceReadsmerged        int64       `json:"disk_device_readsmerged"`
		DiskDeviceSectorsread        int64       `json:"disk_device_sectorsread"`
		DiskDeviceSectorswritten     int64       `json:"disk_device_sectorswritten"`
		DiskDeviceTimeforops         int64       `json:"disk_device_timeforops"`
		DiskDeviceTimereading        int64       `json:"disk_device_timereading"`
		DiskDeviceTimewriting        int64       `json:"disk_device_timewriting"`
		DiskDeviceWeightedtimeforops int64       `json:"disk_device_weightedtimeforops"`
		DiskDeviceWrites             int64       `json:"disk_device_writes"`
		DiskDeviceWritesmerged       int64       `json:"disk_device_writesmerged"`
		HostName                     string      `json:"host_name"`
		HostUUID                     string      `json:"host_uuid"`
		NetHostReceivedBytes         json.Number `json:"net_host_receivedBytes"`
		NetHostReceivedCompressed    int64       `json:"net_host_receivedCompressed"`
		NetHostReceivedDrop          int64       `json:"net_host_receivedDrop"`
		NetHostReceivedErrs          int64       `json:"net_host_receivedErrs"`
		NetHostReceivedFifo          int64       `json:"net_host_receivedFifo"`
		NetHostReceivedFrame         int64       `json:"net_host_receivedFrame"`
		NetHostReceivedMulticast     int64       `json:"net_host_receivedMulticast"`
		NetHostReceivedPackets       int64       `json:"net_host_receivedPackets"`
		NetHostSpeed                 int64       `json:"net_host_speed"`
		NetHostTransmittedBytes      int64       `json:"net_host_transmittedBytes"`
		NetHostTransmittedCarrier    int64       `json:"net_host_transmittedCarrier"`
		NetHostTransmittedColls      int64       `json:"net_host_transmittedColls"`
		NetHostTransmittedCompressed int64       `json:"net_host_transmittedCompressed"`
		NetHostTransmittedDrop       int64       `json:"net_host_transmittedDrop"`
		NetHostTransmittedErrs       int64       `json:"net_host_transmittedErrs"`
		NetHostTransmittedFifo       int64       `json:"net_host_transmittedFifo"`
		NetHostTransmittedPackets    int64       `json:"net_host_transmittedPackets"`
		PsiFullIoAvg10               float64     `json:"psi_full_io_avg10"`
		PsiFullIoAvg300              float64     `json:"psi_full_io_avg300"`
		PsiFullIoAvg60               float64     `json:"psi_full_io_avg60"`
		PsiFullIoTotal               float64     `json:"psi_full_io_total"`
		PsiFullMemAvg10              float64     `json:"psi_full_mem_avg10"`
		PsiFullMemAvg300             float64     `json:"psi_full_mem_avg300"`
		PsiFullMemAvg60              float64     `json:"psi_full_mem_avg60"`
		PsiFullMemTotal              float64     `json:"psi_full_mem_total"`
		PsiSomeCPUAvg10              float64     `json:"psi_some_cpu_avg10"`
		PsiSomeCPUAvg300             float64     `json:"psi_some_cpu_avg300"`
		PsiSomeCPUAvg60              float64     `json:"psi_some_cpu_avg60"`
		PsiSomeCPUTotal              float64     `json:"psi_some_cpu_total"`
		PsiSomeIoAvg10               float64     `json:"psi_some_io_avg10"`
		PsiSomeIoAvg300              float64     `json:"psi_some_io_avg300"`
		PsiSomeIoAvg60               float64     `json:"psi_some_io_avg60"`
		PsiSomeIoTotal               float64     `json:"psi_some_io_total"`
		PsiSomeMemAvg10              float64     `json:"psi_some_mem_avg10"`
		PsiSomeMemAvg300             float64     `json:"psi_some_mem_avg300"`
		PsiSomeMemAvg60              float64     `json:"psi_some_mem_avg60"`
		PsiSomeMemTotal              float64     `json:"psi_some_mem_total"`
		RAMActive                    int64       `json:"ram_Active"`
		RAMActiveAanon               int64       `json:"ram_ActiveAanon"`
		RAMActiveFile                int64       `json:"ram_ActiveFile"`
		RAMAnonHugePages             int64       `json:"ram_AnonHugePages"`
		RAMAnonPages                 int64       `json:"ram_AnonPages"`
		RAMAvailable                 int64       `json:"ram_Available"`
		RAMBounce                    int64       `json:"ram_Bounce"`
		RAMBuffers                   int64       `json:"ram_Buffers"`
		RAMCached                    int64       `json:"ram_Cached"`
		RAMCommitLimit               int64       `json:"ram_CommitLimit"`
		RAMCommittedAS               int64       `json:"ram_CommittedAS"`
		RAMDirectMap1G               int64       `json:"ram_DirectMap1G"`
		RAMDirectMap2M               int64       `json:"ram_DirectMap2M"`
		RAMDirectMap4k               int64       `json:"ram_DirectMap4k"`
		RAMDirty                     int64       `json:"ram_Dirty"`
		RAMFree                      int64       `json:"ram_Free"`
		RAMHardwareCorrupted         int64       `json:"ram_HardwareCorrupted"`
		RAMHugePagesFree             int64       `json:"ram_HugePagesFree"`
		RAMHugePagesRsvd             int64       `json:"ram_HugePagesRsvd"`
		RAMHugePagesSurp             int64       `json:"ram_HugePagesSurp"`
		RAMHugePagesTotal            int64       `json:"ram_HugePagesTotal"`
		RAMHugepagesize              int64       `json:"ram_Hugepagesize"`
		RAMHugetlb                   int64       `json:"ram_Hugetlb"`
		RAMInactive                  int64       `json:"ram_Inactive"`
		RAMInactiveAanon             int64       `json:"ram_InactiveAanon"`
		RAMInactiveFile              int64       `json:"ram_InactiveFile"`
		RAMKernelStack               int64       `json:"ram_KernelStack"`
		RAMMapped                    int64       `json:"ram_Mapped"`
		RAMMlocked                   int64       `json:"ram_Mlocked"`
		RAMNFSUnstable               int64       `json:"ram_NFSUnstable"`
		RAMPageTables                int64       `json:"ram_PageTables"`
		RAMSReclaimable              int64       `json:"ram_SReclaimable"`
		RAMSUnreclaim                int64       `json:"ram_SUnreclaim"`
		RAMShmem                     int64       `json:"ram_Shmem"`
		RAMShmemHugePages            int64       `json:"ram_ShmemHugePages"`
		RAMShmemPmdMapped            int64       `json:"ram_ShmemPmdMapped"`
		RAMSlab                      int64       `json:"ram_Slab"`
		RAMSwapCached                int64       `json:"ram_SwapCached"`
		RAMSwapFree                  int64       `json:"ram_SwapFree"`
		RAMSwapTotal                 int64       `json:"ram_SwapTotal"`
		RAMTotal                     int64       `json:"ram_Total"`
		RAMUnevictable               int64       `json:"ram_Unevictable"`
		RAMVmallocChunk              int64       `json:"ram_VmallocChunk"`
		RAMVmallocTotal              int64       `json:"ram_VmallocTotal"`
		RAMVmallocUsed               int64       `json:"ram_VmallocUsed"`
		RAMWriteback                 int64       `json:"ram_Writeback"`
		RAMWritebackTmp              int64       `json:"ram_WritebackTmp"`
	} `json:"host"`
}

type dbValuesMetrics struct {
	Cpu          sql.NullInt64
	Ram          sql.NullInt64
	Disk         sql.NullInt64
	IoReadBytes  sql.NullFloat64
	IoWriteBytes sql.NullFloat64
	NetTxBytes   sql.NullFloat64
	NetRxBytes   sql.NullFloat64
	TimeStamp    sql.NullString
}

type dbValuesMetricsArray struct {
	Cpu          []int64   `json:"CpuUsage"`
	Ram          []int64   `json:"RamUsage"`
	Disk         []int64   `json:"DiskUsage"`
	IoReadBytes  []float64 `json:"IoReadBytes"`
	IoWriteBytes []float64 `json:"IoWriteBytes"`
	NetTxBytes   []float64 `json:"NetTxBytes"`
	NetRxBytes   []float64 `json:"NetRxBytes"`
	TimeStamp    []string  `json:"TimeStamp"`
}

type dbValuesMetricsStandard struct {
	Cpu          sql.NullFloat64
	Ram          sql.NullFloat64
	Disk         sql.NullFloat64
	IoReadBytes  sql.NullFloat64
	IoWriteBytes sql.NullFloat64
	NetTxBytes   sql.NullFloat64
	NetRxBytes   sql.NullFloat64
	TimeStamp    sql.NullString
}
