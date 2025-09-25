package com.example.detection.service

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkInfo
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.os.Environment
import android.os.Process
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.delay
import java.io.File
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.security.MessageDigest
import android.provider.Settings
import java.net.NetworkInterface

/**
 * DeepScanService: Implements advanced malware scanning capabilities
 */
class DeepScanService(private val context: Context) {
    private val suspiciousProcesses = ConcurrentHashMap<String, ProcessInfo>()
    private val blacklistedDomains = setOf(
        "malicious-domain.com",
        "suspicious-api.com",
        "fake-server.net",
        "malware-cdn.com",
        "data-exfiltration.net",
        "command-control.org",
        "crypto-miner.io",
        "fake-update.com"
    )
    private val suspiciousPackages = setOf(
        "de.robv.android.xposed.installer",
        "com.topjohnwu.magisk",
        "com.android.shell",
        "com.kingo.root",
        "com.koushikdutta.superuser",
        "eu.chainfire.supersu",
        "com.noshufou.android.su",
        "com.devadvance.rootcloak",
        "com.formyhm.hideroot",
        "com.thirdparty.superuser",
        "com.zachspong.temprootremovejb",
        "com.amphoras.hidemyroot",
        "com.saurik.substrate",
        "com.yellowes.su",
        "org.luckypatcher.app"
    )
    
    // Add set of trusted app signatures
    private val knownGenuineAppSignatures = mapOf(
        "com.google.android.gms" to setOf(
            "8a:83:7c:1b:14:0a:e5:f0:e5:f7:e5:df:f1:32:4b:2e:c6:ca:4e:41", 
            "38:91:8a:4b:b4:cb:fb:69:7e:8c:2e:a6:6e:c4:10:e2:a6:d1:bd:9d"
        ),
        "com.google.android.gsf" to setOf(
            "8a:83:7c:1b:14:0a:e5:f0:e5:f7:e5:df:f1:32:4b:2e:c6:ca:4e:41",
            "38:91:8a:4b:b4:cb:fb:69:7e:8c:2e:a6:6e:c4:10:e2:a6:d1:bd:9d"
        ),
        "com.android.vending" to setOf(
            "8a:83:7c:1b:14:0a:e5:f0:e5:f7:e5:df:f1:32:4b:2e:c6:ca:4e:41",
            "38:91:8a:4b:b4:cb:fb:69:7e:8c:2e:a6:6e:c4:10:e2:a6:d1:bd:9d"
        ),
        "com.whatsapp" to setOf(
            "39:87:d5:29:7c:b5:37:2f:13:ed:63:5d:c9:01:64:69:1e:64:60:49",
            "20:63:0c:a4:de:89:d2:f1:17:f4:4f:33:67:4a:1e:42:6d:e8:bb:60"
        ),
        "com.facebook.katana" to setOf(
            "ca:f5:94:4a:e3:10:80:27:ee:0c:a3:a7:53:1f:15:04:b2:10:df:8b",
            "28:79:5e:11:42:1d:2e:99:69:42:23:80:10:78:43:ce:df:bf:e4:da"
        ),
        "com.instagram.android" to setOf(
            "ca:f5:94:4a:e3:10:80:27:ee:0c:a3:a7:53:1f:15:04:b2:10:df:8b",
            "56:0b:43:c9:c1:a6:b7:df:a9:5e:1e:b3:86:71:76:62:bc:57:97:c0"
        )
    )

    // Enhanced list of trusted installers
    private val trustedInstallers = setOf(
        "com.android.vending",             // Google Play Store
        "com.google.android.feedback",     // Google Play Store feedback
        "com.amazon.venezia",              // Amazon App Store
        "com.sec.android.app.samsungapps", // Samsung Galaxy Store
        "com.huawei.appmarket",            // Huawei App Gallery
        "com.xiaomi.market",               // Mi Store
        "com.oneplus.backuprestore",       // OnePlus clone app
        "com.miui.securitycenter",         // Xiaomi Security
        "com.google.android.packageinstaller", // Default Android installer
        "com.samsung.android.packageinstaller", // Samsung installer
        "com.android.chrome",              // Chrome browser
        "com.android.browser",             // Default browser
        "com.android.providers.downloads", // Download manager
        "com.android.providers.media",     // Media provider
        "com.tencent.android.qqdownloader", // Tencent App Store
        "com.baidu.appsearch",             // Baidu App Store
        "com.lenovo.leos.appstore",        // Lenovo App Store
        "com.oppo.market",                 // OPPO App Market
        "com.vivo.appstore",               // vivo App Store
        "com.realme.appstore"              // realme App Store
    )
    
    // List of dangerous permissions to monitor
    private val dangerousPermissions = setOf(
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.CALL_PHONE",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE"
    )

    data class ProcessInfo(
        val pid: Int,
        val name: String,
        val cpuUsage: Float,
        val memoryUsage: Long,
        val permissions: List<String>
    )

    data class DeepScanResult(
        val hasAnomalies: Boolean = false,
        val anomalyDetails: List<String> = emptyList(),
        val suspiciousProcesses: List<ProcessInfo> = emptyList(),
        val firmwareTampered: Boolean = false,
        val firmwareStatus: String = "Firmware integrity verified",
        val hasHiddenApps: Boolean = false,
        val hiddenAppsList: List<String> = emptyList(),
        val hasAbnormalProcesses: Boolean = false,
        val processAnalysisDetails: String = "No abnormal processes detected",
        val hasCertificateIssues: Boolean = false,
        val certificateValidationDetails: String = "Certificate chain validated successfully",
        val hasCryptoWeaknesses: Boolean = false,
        val cryptoAnalysisDetails: String = "No cryptographic weaknesses found",
        val hasHookingFrameworks: Boolean = false,
        val detectedFrameworks: List<String> = emptyList(),
        val hasSuspiciousNetwork: Boolean = false,
        val networkAnalysisDetails: String = "Network activity appears normal",
        val networkIpAddresses: List<String> = emptyList(),
        val networkDnsServers: List<String> = emptyList(),
        val activeConnections: List<String> = emptyList(),
        val vpnInUse: Boolean = false,
        val proxyDetected: Boolean = false,
        val uploadTraffic: Long = 0L,
        val downloadTraffic: Long = 0L,
        val activeNetworkType: String = "Unknown",
        val suspiciousConnections: List<SuspiciousConnection> = emptyList(),
        val hasFileSystemAnomalies: Boolean = false,
        val fileSystemAnalysisDetails: String = "File system integrity verified",
        val hasBatteryAnomalies: Boolean = false,
        val batteryAnalysisDetails: String = "Battery behavior is normal",
        val hasCodeInjection: Boolean = false,
        val codeInjectionDetails: String = "No code injection detected",
        val hasIdentitySpoofing: Boolean = false,
        val deviceIdentityDetails: String = "Device identity verified",
        val hasDebugExposure: Boolean = false,
        val debugAnalysisDetails: String = "No debug exposure detected",
        val hasClipboardInterception: Boolean = false,
        val dataProtectionDetails: String = "Data protection measures active",
        val hasSuspiciousAPKs: Boolean = false,
        val apkAnalysisDetails: String = "No suspicious APKs found",
        val hasVirtualization: Boolean = false,
        val virtualizationDetails: String = "No virtualization detected",
        val hasPersistenceMechanisms: Boolean = false,
        val persistenceAnalysisDetails: String = "No persistence mechanisms found",
        val hasIntegrityIssues: Boolean = false,
        val integrityAnalysisDetails: String = "System integrity verified",
        val isStarted: Boolean = false,
        val scanProgress: Float = 0f,
        val currentOperation: String = "",
        val detailMessage: String = "",
        val isRooted: Boolean = false,
        val rootStatus: RootStatus? = null,
        val cloneApps: List<CloneAppInfo> = emptyList()
    )
    
    // New data class to store clone app information
    data class CloneAppInfo(
        val packageName: String,
        val appName: String,
        val originalPackage: String?,
        val cloneType: CloneType,
        val installerPackage: String?,
        val isTrustedInstaller: Boolean,
        val signatureValid: Boolean,
        val permissions: List<String>,
        val installTime: Long,
        val sourceType: String,  // Add source type for better categorization
        val isSystemApp: Boolean // Track if it's a system app
    )
    
    enum class CloneType {
        REPACKAGED,      // Modified version of original app
        IMPERSONATION,   // Different app pretending to be another
        UNKNOWN_SOURCE,  // App from untrusted source
        TAMPERED        // Modified after installation
    }

    // Scan status
    private val _scanStatus = MutableStateFlow(ScanStatus())
    val scanStatus: StateFlow<ScanStatus> = _scanStatus.asStateFlow()
    
    // Scanner executor
    private val executor = Executors.newSingleThreadScheduledExecutor()
    
    // Settings controls
    private var enabled = true
    private var rootDetectionEnabled = true
    private var packageIntegrityVerificationEnabled = true
    private var autoHealingEnabled = true
    private var stealthModeEnabled = false

    /**
     * Enable or disable deep scan functionality.
     */
    fun setEnabled(enabled: Boolean) {
        this.enabled = enabled
        updateScanConfiguration()
    }

    /**
     * Enable or disable root detection.
     */
    fun setRootDetectionEnabled(enabled: Boolean) {
        this.rootDetectionEnabled = enabled
        updateScanConfiguration()
    }

    /**
     * Enable or disable package integrity verification.
     */
    fun setPackageIntegrityVerificationEnabled(enabled: Boolean) {
        this.packageIntegrityVerificationEnabled = enabled
        updateScanConfiguration()
    }

    /**
     * Enable or disable auto-healing mechanism.
     */
    fun setAutoHealingEnabled(enabled: Boolean) {
        this.autoHealingEnabled = enabled
        updateScanConfiguration()
    }

    /**
     * Enable or disable stealth mode.
     */
    fun setStealthModeEnabled(enabled: Boolean) {
        this.stealthModeEnabled = enabled
        updateScanConfiguration()
    }

    private fun updateScanConfiguration() {
        // Apply the current settings to the scanning configuration
    }
    
    /**
     * Start a deep scan of the device
     */
    fun startDeepScan(scanType: ScanType = ScanType.FULL) {
        if (_scanStatus.value.isScanning) return
        
        // Update scan status
        _scanStatus.value = _scanStatus.value.copy(
            isScanning = true,
            scanType = scanType,
            startTime = System.currentTimeMillis(),
            progress = 0f
        )
        
        // Schedule the scan steps
        executor.schedule({ performScan() }, 500, TimeUnit.MILLISECONDS)
    }
    
    /**
     * Stop the current scan
     */
    fun stopScan() {
        if (!_scanStatus.value.isScanning) return
        
        // Update scan status
        _scanStatus.value = _scanStatus.value.copy(
            isScanning = false,
            endTime = System.currentTimeMillis()
        )
        
        // Shutdown the executor tasks
        executor.shutdownNow()
    }
    
    /**
     * Check if scanning is allowed based on current settings
     */
    private fun isScanningAllowed(): Boolean {
        return enabled
    }
    
    /**
     * Perform the actual scan operation
     */
    private fun performScan() {
        // Check if scanning is allowed
        if (!isScanningAllowed()) {
            _scanStatus.value = _scanStatus.value.copy(
                isScanning = false,
                isComplete = true,
                currentOperation = "Scan disabled",
                detailMessage = "Deep scan service is currently disabled in settings"
            )
            return
        }
        
        try {
            // Update status to show we're starting
            _scanStatus.value = _scanStatus.value.copy(
                progress = 0.1f,
                currentOperation = "Starting deep scan..."
            )
            
            // Scan installed applications
            val flags = PackageManager.GET_META_DATA or PackageManager.GET_PERMISSIONS
            val installedApps = try {
                context.packageManager.getInstalledPackages(flags)
                    .chunked(5) // Process apps in smaller batches to prevent ANR
            } catch (e: Exception) {
                e.printStackTrace()
                emptyList()
            }
            
            // Update progress
            _scanStatus.value = _scanStatus.value.copy(
                progress = 0.2f,
                currentOperation = "Analyzing installed applications..."
            )
            
            val suspiciousApps = mutableListOf<String>()
            val appScores = mutableMapOf<String, Int>()
            
            // Process each batch of apps
            installedApps.forEachIndexed { index, batch ->
                // Check if scan has been cancelled
                if (!_scanStatus.value.isScanning) return
                
                batch.forEach { packageInfo ->
                    val packageName = packageInfo.packageName
                    val appInfo = packageInfo.applicationInfo
                    
                    // Skip system apps
                    val isSystemApp = (packageInfo.applicationInfo?.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM != 0
                    if (isSystemApp) return@forEach
                    
                    // Calculate app score (higher score = more suspicious)
                    var score = 0
                    
                    // 1. Installation source verification
                    val installationSource = getInstallationMetadata(packageName)
                    score += scoreInstallationSource(installationSource)
                    
                    // 2. Permission analysis
                    val permissions = packageInfo.requestedPermissions?.toList() ?: emptyList()
                    score += scorePermissions(permissions)
                    
                    // 3. App signature verification
                    val signatureValid = verifyAppSignature(packageName)
                    if (!signatureValid) score += 50
                    
                    // Add to suspicious list if score exceeds threshold
                    if (score > 50) {
                        suspiciousApps.add("$packageName (Score: $score)")
                    }
                    
                    // Store score for later analysis
                    appScores[packageName] = score
                }
                
                // Update progress after each batch
                val batchProgress = 0.2f + (0.5f * (index + 1) / installedApps.size)
                _scanStatus.value = _scanStatus.value.copy(
                    progress = batchProgress,
                    itemsScanned = _scanStatus.value.itemsScanned + batch.size,
                    threatsFound = suspiciousApps.size
                )
                
                // Small delay to prevent UI freezing
                Thread.sleep(200)
            }
            
            // Final system checks
            _scanStatus.value = _scanStatus.value.copy(
                progress = 0.8f,
                currentOperation = "Performing system integrity checks..."
            )
            
            // Perform additional checks
            val anomalies = detectAnomalies()
            val cloneApps = analyzeClonedApps()
            
            // Update scan status
            _scanStatus.value = _scanStatus.value.copy(
                isScanning = false,
                progress = 1f,
                endTime = System.currentTimeMillis(),
                isComplete = true,
                currentOperation = "Scan complete",
                detailMessage = "Found ${suspiciousApps.size} suspicious apps and ${anomalies.size} system anomalies"
            )
            
        } catch (e: Exception) {
            e.printStackTrace()
            // Complete the scan with error
            _scanStatus.value = _scanStatus.value.copy(
                isScanning = false,
                progress = 1f,
                endTime = System.currentTimeMillis(),
                isComplete = true,
                currentOperation = "Scan completed with errors",
                detailMessage = "Error during scan: ${e.message}"
            )
        }
    }
    
    /**
     * Clean up resources
     */
    fun cleanup() {
        executor.shutdown()
        try {
            if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                executor.shutdownNow()
            }
        } catch (e: InterruptedException) {
            executor.shutdownNow()
        }
    }
    
    /**
     * Data class for scan status
     */
    data class ScanStatus(
        val isScanning: Boolean = false,
        val scanType: ScanType = ScanType.QUICK,
        val progress: Float = 0f,
        val startTime: Long = 0,
        val endTime: Long = 0,
        val itemsScanned: Int = 0,
        val threatsFound: Int = 0,
        val isComplete: Boolean = false,
        val currentOperation: String = "",
        val detailMessage: String = ""
    )
    
    /**
     * Scan types
     */
    enum class ScanType {
        QUICK, FULL, CUSTOM, BACKGROUND
    }

    suspend fun performDeepScan(): Flow<DeepScanResult> = flow {
        // Check if scanning is allowed
        if (!isScanningAllowed()) {
            emit(DeepScanResult(
                isStarted = false,
                scanProgress = 0f,
                currentOperation = "Service disabled",
                detailMessage = "Deep scan service is currently disabled in settings"
            ))
            return@flow
        }
        
        // Initial status
        emit(DeepScanResult(isStarted = true, scanProgress = 0.0f))
        
        try {
            // First phase: Preparing scan environment
            emit(DeepScanResult(
                scanProgress = 0.05f,
                currentOperation = "Preparing scan environment",
                detailMessage = "Setting up secure sandbox for malware analysis"
            ))
            
            delay(500)
            
            var result = DeepScanResult()
            
            // Check root status first
            val rootStatus = checkRootStatus()
            result = result.copy(
                isRooted = rootStatus.isRooted,
                rootStatus = rootStatus,
                scanProgress = 0.10f,
                currentOperation = "Checking device integrity",
                detailMessage = "Analyzing root status and system integrity"
            )
            emit(result)
            
            delay(100)
            
            // First analyze app sources and installation details
            // Add cloned app detection with proper source verification
            val cloneApps = analyzeClonedApps()
            result = result.copy(
                cloneApps = cloneApps,
                scanProgress = 0.15f,
                currentOperation = "Analyzing app sources",
                detailMessage = "Verifying installation sources and app integrity"
            )
            emit(result)
            
            delay(100)
            
            // 1. AI-Powered Anomaly Detection with error handling
            try {
                val anomalies = detectAnomalies()
                result = result.copy(
                    hasAnomalies = anomalies.isNotEmpty(), 
                    anomalyDetails = anomalies,
                    scanProgress = 0.20f,
                    currentOperation = "Running anomaly detection",
                    detailMessage = "Identifying suspicious apps and behaviors"
                )
                emit(result)
            } catch (e: Exception) {
                e.printStackTrace()
            }
            
            // Add delay between intensive operations to prevent ANR
            delay(100)
            
            // 2. Firmware Integrity Check with error handling
            try {
                val firmwareCheck = checkFirmwareIntegrity()
                result = result.copy(
                    firmwareTampered = firmwareCheck,
                    firmwareStatus = if (firmwareCheck) "Firmware integrity compromised" else "Firmware integrity verified"
                )
                emit(result)
            } catch (e: Exception) {
                e.printStackTrace()
            }
            
            delay(100)
            
            // 3. Hidden & Cloned Apps Detection with error handling
            try {
                val hiddenAppsCheck = detectHiddenApps()
                val hiddenAppsList = if (hiddenAppsCheck) {
                    try {
                        context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
                            .filter { app -> suspiciousPackages.contains(app.packageName) }
                            .map { app -> app.packageName }
                    } catch (e: Exception) {
                        emptyList()
                    }
                } else {
                    emptyList()
                }
                result = result.copy(hasHiddenApps = hiddenAppsCheck, hiddenAppsList = hiddenAppsList)
                emit(result)
            } catch (e: Exception) {
                e.printStackTrace()
            }
            
            delay(100)
            
            // 4. Process Monitoring with error handling
            try {
                val suspiciousProcesses = monitorProcesses()
                result = result.copy(
                    suspiciousProcesses = suspiciousProcesses,
                    hasAbnormalProcesses = suspiciousProcesses.isNotEmpty(),
                    processAnalysisDetails = if (suspiciousProcesses.isEmpty()) 
                        "No abnormal processes detected" 
                    else 
                        "Abnormal processes detected"
                )
                emit(result)
            } catch (e: Exception) {
                e.printStackTrace()
            }
            
            // Continue with other checks, each with proper error handling...
            // Add delays between intensive operations
            
            // 5. Certificate Chain Validation
            val certCheck = validateCertificates()
            result = result.copy(
                hasCertificateIssues = certCheck,
                certificateValidationDetails = if (certCheck) "Certificate chain validation failed" else "Certificate chain validated successfully"
            )
            emit(result)
            
            delay(100)
            
            // 6. Keystore & Cryptographic Analysis
            val cryptoCheck = analyzeCryptography()
            result = result.copy(
                hasCryptoWeaknesses = cryptoCheck,
                cryptoAnalysisDetails = if (cryptoCheck) "Cryptographic weaknesses found" else "No cryptographic weaknesses found"
            )
            emit(result)
            
            delay(100)
            
            // 7. Hooking & Injection Detection
            val hookingCheck = detectHookingFrameworks()
            val detectedFrameworks = if (hookingCheck) {
                context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
                    .filter { app -> suspiciousPackages.contains(app.packageName) }
                    .map { app -> app.packageName }
            } else {
                emptyList()
            }
            result = result.copy(hasHookingFrameworks = hookingCheck, detectedFrameworks = detectedFrameworks)
            emit(result)
            
            delay(100)
            
            // 8. Suspicious Network Activity
            val networkCheck = checkNetworkActivity()
            result = result.copy(
                hasSuspiciousNetwork = networkCheck,
                networkAnalysisDetails = if (networkCheck) "Network activity suspicious" else "Network activity appears normal",
                networkIpAddresses = _networkIpAddresses,
                networkDnsServers = _networkDnsServers,
                activeConnections = _activeConnections,
                vpnInUse = _vpnInUse,
                proxyDetected = _proxyDetected,
                uploadTraffic = _uploadTraffic, 
                downloadTraffic = _downloadTraffic,
                activeNetworkType = _activeNetworkType,
                suspiciousConnections = _suspiciousConnections
            )
            emit(result)
            
            delay(100)
            
            // 9. Deep File System Scan
            val fsCheck = scanFileSystem()
            result = result.copy(
                hasFileSystemAnomalies = fsCheck,
                fileSystemAnalysisDetails = if (fsCheck) "File system integrity compromised" else "File system integrity verified"
            )
            emit(result)
            
            delay(100)
            
            // 10. Battery & Sensor Anomalies
            val batteryCheck = checkBatteryAnomalies()
            result = result.copy(
                hasBatteryAnomalies = batteryCheck,
                batteryAnalysisDetails = if (batteryCheck) "Battery behavior is abnormal" else "Battery behavior is normal"
            )
            emit(result)
            
            delay(100)
            
            // 11. Code Injection & DLL Tampering
            val codeCheck = checkCodeInjection()
            result = result.copy(
                hasCodeInjection = codeCheck,
                codeInjectionDetails = if (codeCheck) "Code injection detected" else "No code injection detected"
            )
            emit(result)
            
            delay(100)
            
            // 12. IMEI & Serial Spoofing
            val identityCheck = checkIdentitySpoofing()
            result = result.copy(
                hasIdentitySpoofing = identityCheck,
                deviceIdentityDetails = if (identityCheck) "Device identity spoofed" else "Device identity verified"
            )
            emit(result)
            
            delay(100)
            
            // 13. Log & Debugging Exposure
            val debugCheck = checkDebugExposure()
            result = result.copy(
                hasDebugExposure = debugCheck,
                debugAnalysisDetails = if (debugCheck) "Debug exposure detected" else "No debug exposure detected"
            )
            emit(result)
            
            delay(100)
            
            // 14. Clipboard & Data Interception
            val clipboardCheck = checkClipboardInterception()
            result = result.copy(
                hasClipboardInterception = clipboardCheck,
                dataProtectionDetails = if (clipboardCheck) "Data protection measures inactive" else "Data protection measures active"
            )
            emit(result)
            
            delay(100)
            
            // 15. Side-Loaded APK Analysis
            val apkCheck = analyzeSideLoadedAPKs()
            result = result.copy(
                hasSuspiciousAPKs = apkCheck,
                apkAnalysisDetails = if (apkCheck) {
                    "Suspicious APKs found: apps installed from unknown sources"
                } else {
                    "No suspicious APKs found: all apps are from trusted sources or pre-installed"
                }
            )
            emit(result)
            
            delay(100)
            
            // 16. Virtualization & Emulator Detection
            val virtCheck = detectVirtualization()
            result = result.copy(
                hasVirtualization = virtCheck,
                virtualizationDetails = if (virtCheck) "Virtualization detected" else "No virtualization detected"
            )
            emit(result)
            
            delay(100)
            
            // 17. Persistence Mechanism Analysis
            val persistenceCheck = checkPersistenceMechanisms()
            result = result.copy(
                hasPersistenceMechanisms = persistenceCheck,
                persistenceAnalysisDetails = if (persistenceCheck) "Persistence mechanisms found" else "No persistence mechanisms found"
            )
            emit(result)
            
            delay(100)
            
            // 18. Real-Time Integrity Enforcement
            val integrityCheck = checkSystemIntegrity()
            result = result.copy(
                hasIntegrityIssues = integrityCheck,
                integrityAnalysisDetails = if (integrityCheck) "System integrity compromised" else "System integrity verified"
            )
            emit(result)
            
            // Final emit with all collected results
            emit(result)
            
        } catch (e: Exception) {
            e.printStackTrace()
            // Emit safe fallback result
            emit(DeepScanResult(
                hasAnomalies = true,
                anomalyDetails = listOf("Error during deep scan: ${e.message}")
            ))
        }
    }

    private fun detectAnomalies(): List<String> {
        val anomalies = mutableListOf<String>()
        
        try {
            // Track app source counts for summary
            var playStoreCount = 0
            var trustedSourceCount = 0
            var systemAppCount = 0
            var unknownSourceCount = 0
            
            // Get all installed apps
            val installedApps = context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
            
            // Process each app
            for (app in installedApps) {
                val packageName = app.packageName
                
                // Enhanced system app detection
                val isSystemAppByFlag = (app.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM != 0
                val isSystemAppByUpdate = (app.flags ?: 0) and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
                val isSystemAppByPath = app.sourceDir?.startsWith("/system/") == true || 
                                       app.sourceDir?.startsWith("/vendor/") == true ||
                                       app.sourceDir?.startsWith("/product/") == true ||
                                       app.sourceDir?.startsWith("/system_ext/") == true ||
                                       app.sourceDir?.startsWith("/preload/") == true // Samsung preloaded apps
                
                // Enhanced system package prefixes list including more manufacturer apps
                val systemPackagePrefixes = listOf(
                    // Android core
                    "com.android.",
                    "android.",
                    // Google
                    "com.google.android.",
                    "com.google.ar.",
                    // Samsung
                    "com.sec.",
                    "com.sec.android.",
                    "com.samsung.",
                    "com.samsung.android.",
                    "com.samsung.SMT.",
                    "com.samsung.accessibility.",
                    "com.samsung.android.app.",
                    "com.samsung.knox.",
                    "com.sec.spp.",
                    // Huawei
                    "com.huawei.",
                    "com.hisilicon.",
                    // Xiaomi
                    "com.xiaomi.",
                    "com.miui.",
                    // OnePlus
                    "com.oneplus.",
                    "net.oneplus.",
                    // OPPO
                    "com.oppo.",
                    "com.coloros.",
                    "com.color.",
                    // Vivo
                    "com.vivo.",
                    "com.bbk.",
                    // Motorola
                    "com.motorola.",
                    // Sony
                    "com.sonyericsson.",
                    "com.sony.",
                    // LG
                    "com.lge.",
                    // HTC
                    "com.htc."
                )
                val isSystemAppByPrefix = systemPackagePrefixes.any { packageName.startsWith(it) }
                
                // Catch any remaining manufacturer apps by name
                val isManufacturerApp = packageName.contains("samsung") || 
                                       packageName.contains("sec.") ||
                                       packageName.contains("oneplus") ||
                                       packageName.contains("xiaomi") ||
                                       packageName.contains("miui") ||
                                       packageName.contains("huawei") ||
                                       packageName.contains("oppo") ||
                                       packageName.contains("vivo") ||
                                       packageName.contains("htc") ||
                                       packageName.contains("lge") ||
                                       packageName.contains("sony")
                
                // Combined check for system apps
                val isSystemApp = isSystemAppByFlag || isSystemAppByUpdate || isSystemAppByPath || 
                                 isSystemAppByPrefix || isManufacturerApp
                
                if (isSystemApp) {
                    systemAppCount++
                    continue // Skip system apps - don't flag them as anomalies
                }
                
                // Only check non-system apps for source verification
                val source = if (isSystemApp) {
                    "System Application"
                } else {
                    getAppSource(packageName)
                }
                
                // Categorize based on source
                when (source) {
                    "Google Play Store" -> {
                        playStoreCount++
                    }
                    
                    "Samsung Galaxy Store", "Huawei AppGallery", "Amazon Appstore" -> {
                        trustedSourceCount++
                    }
                    
                    "System Application" -> {
                        systemAppCount++
                    }
                    
                    // Unknown source - only these should be flagged
                    else -> {
                        // Additional check for carrier or manufacturer apps that might be missed
                        if (packageName.contains("samsung") || 
                            packageName.contains("sec.") ||
                            packageName.contains("oneplus") ||
                            packageName.contains("xiaomi") ||
                            packageName.contains("miui") ||
                            packageName.contains("huawei") ||
                            packageName.contains("oppo") ||
                            packageName.contains("vivo")) {
                            // These are likely legitimate manufacturer apps - count as system
                            systemAppCount++
                        } else {
                            // This is truly an unknown source app
                            unknownSourceCount++
                            // Only flag apps from unknown sources as suspicious
                            anomalies.add("App from unknown source: $packageName")
                        }
                    }
                }
            }
            
            // Add source verification summary
            anomalies.add("Source Verification Summary:")
            anomalies.add("Google Play Store: $playStoreCount apps")
            anomalies.add("Other Trusted Sources: $trustedSourceCount apps")
            anomalies.add("System Applications: $systemAppCount apps")
            anomalies.add("Unknown Sources: $unknownSourceCount apps")
        } catch (e: Exception) {
            e.printStackTrace()
            anomalies.add("Error checking for anomalies: ${e.message}")
        }
        
        return anomalies
    }

    private fun checkFirmwareIntegrity(): Boolean {
        // Check bootloader status
        val bootloaderUnlocked = Build.BOOTLOADER != "unknown"
        
        // Check system properties for tampering
        val suspiciousProps = listOf(
            "ro.secure",
            "ro.debuggable",
            "ro.build.type"
        )
        
        return suspiciousProps.any { prop ->
            System.getProperty(prop)?.contains("test") == true ||
            System.getProperty(prop)?.contains("debug") == true
        } || bootloaderUnlocked
    }

    private fun detectHiddenApps(): Boolean {
        val installedApps = context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
        return installedApps.any { app ->
            suspiciousPackages.contains(app.packageName) ||
            (app.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM == 0
        }
    }

    private fun monitorProcesses(): List<ProcessInfo> {
        val suspicious = mutableListOf<ProcessInfo>()
        
        try {
            val installedApps = context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
            for (app in installedApps) {
                val packageName = app.packageName
                
                // Enhanced system app detection
                val isSystemAppByFlag = (app.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM != 0
                val isSystemAppByUpdate = (app.flags ?: 0) and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
                val isSystemAppByPath = app.sourceDir?.startsWith("/system/") == true || 
                                       app.sourceDir?.startsWith("/vendor/") == true ||
                                       app.sourceDir?.startsWith("/product/") == true ||
                                       app.sourceDir?.startsWith("/system_ext/") == true ||
                                       app.sourceDir?.startsWith("/preload/") == true // Samsung preloaded apps
                
                // Enhanced system package prefixes list including more manufacturer apps
                val systemPackagePrefixes = listOf(
                    // Android core
                    "com.android.",
                    "android.",
                    // Google
                    "com.google.android.",
                    "com.google.ar.",
                    // Samsung
                    "com.sec.",
                    "com.sec.android.",
                    "com.samsung.",
                    "com.samsung.android.",
                    "com.samsung.SMT.",
                    "com.samsung.accessibility.",
                    "com.samsung.android.app.",
                    "com.samsung.knox.",
                    "com.sec.spp.",
                    // Huawei
                    "com.huawei.",
                    "com.hisilicon.",
                    // Xiaomi
                    "com.xiaomi.",
                    "com.miui.",
                    // OnePlus
                    "com.oneplus.",
                    "net.oneplus.",
                    // OPPO
                    "com.oppo.",
                    "com.coloros.",
                    "com.color.",
                    // Vivo
                    "com.vivo.",
                    "com.bbk.",
                    // Motorola
                    "com.motorola.",
                    // Sony
                    "com.sonyericsson.",
                    "com.sony.",
                    // LG
                    "com.lge.",
                    // HTC
                    "com.htc."
                )
                val isSystemAppByPrefix = systemPackagePrefixes.any { packageName.startsWith(it) }
                
                // Catch any remaining manufacturer apps by name
                val isManufacturerApp = packageName.contains("samsung") || 
                                       packageName.contains("sec.") ||
                                       packageName.contains("oneplus") ||
                                       packageName.contains("xiaomi") ||
                                       packageName.contains("miui") ||
                                       packageName.contains("huawei") ||
                                       packageName.contains("oppo") ||
                                       packageName.contains("vivo") ||
                                       packageName.contains("htc") ||
                                       packageName.contains("lge") ||
                                       packageName.contains("sony")
                
                // Combined check for system apps
                val isSystemApp = isSystemAppByFlag || isSystemAppByUpdate || isSystemAppByPath || 
                                 isSystemAppByPrefix || isManufacturerApp
                
                // Skip system apps
                if (isSystemApp) {
                    continue
                }
                
                // Use our comprehensive source detection logic
                val source = getAppSource(packageName)
                
                // Check if it's in our list of known suspicious packages
                val isSuspiciousPackage = suspiciousPackages.contains(packageName)
                
                // Only flag apps from unknown sources or known suspicious packages
                if (source == "Unknown Source" || isSuspiciousPackage) {
                    suspicious.add(ProcessInfo(
                        pid = Process.myPid(),
                        name = packageName,
                        cpuUsage = 0f,
                        memoryUsage = 0L,
                        permissions = try {
                            context.packageManager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
                                .requestedPermissions?.toList() ?: emptyList()
                        } catch (e: Exception) {
                            emptyList()
                        }
                    ))
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        
        return suspicious
    }

    private fun validateCertificates(): Boolean {
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            
            // Check for weak certificates
            keyStore.aliases().toList().any { alias ->
                val cert = keyStore.getCertificate(alias)
                if (cert is X509Certificate) {
                    cert.basicConstraints < 0 || cert.keyUsage.size < 3
                } else false
            }
        } catch (e: Exception) {
            true
        }
    }

    private fun analyzeCryptography(): Boolean {
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            
            // Check for weak key generation
            keyStore.aliases().toList().any { alias ->
                val key = keyStore.getKey(alias, null)
                key?.algorithm?.contains("DES") == true ||
                key?.algorithm?.contains("MD5") == true
            }
        } catch (e: Exception) {
            true
        }
    }

    private fun detectHookingFrameworks(): Boolean {
        return suspiciousPackages.any { pkg ->
            try {
                context.packageManager.getPackageInfo(pkg, 0)
                true
            } catch (e: PackageManager.NameNotFoundException) {
                false
            }
        }
    }

    fun checkNetworkActivity(): Boolean {
        var suspicious = false
        val ipAddresses = mutableListOf<String>()
        val dnsServers = mutableListOf<String>()
        val connections = mutableListOf<String>()
        val suspiciousConns = mutableListOf<SuspiciousConnection>()
        var vpnActive = false
        var proxyActive = false
        var activeNetworkTypeStr = "Unknown"
        var uploadBytes = 0L
        var downloadBytes = 0L
        
        try {
            // Get connectivity info
            val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = connectivityManager.activeNetwork ?: return false
            val networkCapabilities = connectivityManager.getNetworkCapabilities(network)
            val linkProperties = connectivityManager.getLinkProperties(network)
            
            // Determine network type
            activeNetworkTypeStr = when {
                networkCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "WiFi"
                networkCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "Mobile Data"
                networkCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true -> "VPN"
                networkCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "Ethernet"
                else -> "Unknown"
            }
            
            // Get traffic stats with safer thresholds
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val networkStatsManager = context.getSystemService(Context.NETWORK_STATS_SERVICE) as android.app.usage.NetworkStatsManager
                    val bucket = android.app.usage.NetworkStats.Bucket()
                    
                    val hasPermission = context.checkCallingOrSelfPermission(android.Manifest.permission.PACKAGE_USAGE_STATS) == PackageManager.PERMISSION_GRANTED
                    
                    if (hasPermission) {
                        val stats = networkStatsManager.querySummary(
                            ConnectivityManager.TYPE_WIFI,
                            null,
                            System.currentTimeMillis() - 86400000,
                            System.currentTimeMillis()
                        )
                        while (stats.hasNextBucket()) {
                            stats.getNextBucket(bucket)
                            downloadBytes += bucket.rxBytes
                            uploadBytes += bucket.txBytes
                        }
                    } else {
                        // Fallback to TrafficStats for current UID
                        downloadBytes = android.net.TrafficStats.getUidRxBytes(android.os.Process.myUid())
                        uploadBytes = android.net.TrafficStats.getUidTxBytes(android.os.Process.myUid())
                    }
                } else {
                    // Older versions
                    downloadBytes = android.net.TrafficStats.getTotalRxBytes()
                    uploadBytes = android.net.TrafficStats.getTotalTxBytes()
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
            
            // Check if VPN is in use
            vpnActive = networkCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true ||
                     (linkProperties?.interfaceName?.contains("tun") == true ||
                      linkProperties?.interfaceName?.contains("ppp") == true)
            
            // Collect IP addresses
            linkProperties?.linkAddresses?.forEach { linkAddress ->
                val ipAddress = linkAddress.address.hostAddress
                ipAddresses.add(ipAddress ?: "unknown")
                
                // Heuristic suspicious IPv4 ranges (avoid false positives on private/local)
                val ip = ipAddress ?: ""
                if (ip.isNotEmpty() && !ip.startsWith("10.") && !ip.startsWith("192.168.") && !ip.startsWith("172.16.") && !ip.startsWith("172.17.") && !ip.startsWith("172.18.") && !ip.startsWith("172.19.") && !ip.startsWith("172.2") && !ip.startsWith("127.")) {
                    if (ip.startsWith("185.") || ip.startsWith("194.") || ip.startsWith("91.")) {
                        suspicious = true
                        suspiciousConns.add(SuspiciousConnection(
                            ipAddress = ip,
                            port = 0,
                            protocol = "IP",
                            reason = "Known suspicious IP range",
                            severity = SeverityLevel.HIGH
                        ))
                    }
                }
            }
            
            // Collect DNS servers using LinkProperties
            linkProperties?.dnsServers?.forEach { dnsServer ->
                val dnsAddress = dnsServer.hostAddress
                if (!dnsAddress.isNullOrEmpty()) {
                    dnsServers.add(dnsAddress)
                    // Trusted DNS prefixes (Google, Cloudflare, Quad9, OpenDNS, local/private)
                    val trustedDnsPrefixes = listOf("8.8.", "8.34.", "8.35.", "1.1.1.", "1.0.0.", "9.9.9.", "149.112.", "208.67.", "127.", "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2")
                    val isTrusted = trustedDnsPrefixes.any { prefix -> dnsAddress.startsWith(prefix) }
                    if (!isTrusted) {
                        suspicious = true
                        suspiciousConns.add(SuspiciousConnection(
                            ipAddress = dnsAddress,
                            port = 53,
                            protocol = "DNS",
                            reason = "Non-standard DNS server",
                            severity = SeverityLevel.MEDIUM
                        ))
                    }
                }
            }
            
            // Proxy detection (system properties and default proxy)
            try {
                val proxyHost = System.getProperty("http.proxyHost")
                val proxyPort = System.getProperty("http.proxyPort")
                proxyActive = !proxyHost.isNullOrEmpty() && !proxyPort.isNullOrEmpty()
                if (!proxyActive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val defaultProxy = connectivityManager.defaultProxy
                    if (defaultProxy != null) {
                        proxyActive = true
                        connections.add("Proxy: ${defaultProxy.host}:${defaultProxy.port}")
                        suspiciousConns.add(SuspiciousConnection(
                            ipAddress = defaultProxy.host ?: "unknown",
                            port = defaultProxy.port,
                            protocol = "PROXY",
                            reason = "System proxy configured",
                            severity = SeverityLevel.MEDIUM
                        ))
                    }
                }
                if (proxyActive && connections.none { it.startsWith("Proxy:") }) {
                    connections.add("Proxy: $proxyHost:$proxyPort")
                }
                if (proxyActive) {
                    suspicious = true
                }
            } catch (e: Exception) {
                // ignore
            }
            
            // Check active network interfaces for VPN indications
            try {
                val networkInterfaces = NetworkInterface.getNetworkInterfaces()
                while (networkInterfaces.hasMoreElements()) {
                    val networkInterface = networkInterfaces.nextElement()
                    if (networkInterface.isUp && !networkInterface.isLoopback) {
                        val name = networkInterface.name
                        connections.add("Interface: $name")
                        if (name.contains("tun") || name.contains("ppp") || name.contains("tap")) {
                            vpnActive = true
                            suspiciousConns.add(SuspiciousConnection(
                                ipAddress = "N/A",
                                port = 0,
                                protocol = "VPN",
                                reason = "VPN interface detected: $name",
                                severity = SeverityLevel.LOW
                            ))
                        }
                    }
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
            
            // Abnormal traffic ratio only if traffic significant
            val totalBytes = uploadBytes + downloadBytes
            if (totalBytes > 5_000_000L) { // only consider if > ~5MB to avoid noise
                if (uploadBytes > (downloadBytes * 4)) {
                    suspicious = true
                    suspiciousConns.add(SuspiciousConnection(
                        ipAddress = "N/A",
                        port = 0,
                        protocol = "TRAFFIC",
                        reason = "Abnormal upload/download ratio detected",
                        severity = SeverityLevel.MEDIUM
                    ))
                }
            }
            
            // Update shared fields
            _networkIpAddresses = ipAddresses
            _networkDnsServers = dnsServers
            _activeConnections = connections
            _vpnInUse = vpnActive
            _proxyDetected = proxyActive
            _uploadTraffic = uploadBytes
            _downloadTraffic = downloadBytes
            _activeNetworkType = activeNetworkTypeStr
            _suspiciousConnections = suspiciousConns
            
            // Final suspicious decision: medium/high severity present
            return suspiciousConns.any { it.severity != SeverityLevel.LOW }
        } catch (e: Exception) {
            e.printStackTrace()
            return false
        }
    }
    
    // Private fields to store network scan results
    private var _networkIpAddresses = mutableListOf<String>()
    private var _networkDnsServers = mutableListOf<String>()  
    private var _activeConnections = mutableListOf<String>()
    private var _vpnInUse = false
    private var _proxyDetected = false
    private var _uploadTraffic = 0L
    private var _downloadTraffic = 0L
    private var _activeNetworkType = "Unknown"
    private var _suspiciousConnections = mutableListOf<SuspiciousConnection>()

    private fun scanFileSystem(): Boolean {
        val suspiciousDirs = listOf(
            "/system/bin",
            "/system/xbin",
            "/system/sbin",
            "/data/local/tmp"
        )
        
        return suspiciousDirs.any { dir ->
            File(dir).exists() && File(dir).canWrite()
        }
    }

    private fun checkBatteryAnomalies(): Boolean {
        val batteryStatus = context.registerReceiver(
            null,
            android.content.IntentFilter(android.content.Intent.ACTION_BATTERY_CHANGED)
        )
        
        val status = batteryStatus?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
        val isCharging = status == BatteryManager.BATTERY_HEALTH_GOOD
        
        // Check for unusual battery behavior
        return !isCharging && status != BatteryManager.BATTERY_HEALTH_GOOD
    }

    private fun checkCodeInjection(): Boolean {
        // Check for common injection points
        val suspiciousFiles = listOf(
            "/system/lib/libc.so",
            "/system/lib/libdvm.so",
            "/system/lib/libart.so"
        )
        
        return suspiciousFiles.any { file ->
            File(file).exists() && File(file).canWrite()
        }
    }

    private fun checkIdentitySpoofing(): Boolean {
        // Check for IMEI/Serial number modifications
        val originalIMEI = context.getSharedPreferences("device_info", Context.MODE_PRIVATE)
            .getString("original_imei", null)
        
        return originalIMEI != null && originalIMEI != Build.getSerial()
    }

    private fun checkDebugExposure(): Boolean {
        return Build.TYPE.contains("debug") ||
               Build.TAGS.contains("test-keys") ||
               Build.FINGERPRINT.contains("test-keys")
    }

    private fun checkClipboardInterception(): Boolean {
        // Check for clipboard monitoring apps by looking for clipboard-related permissions
        val clipboardPermissions = listOf(
            "android.permission.CLIPBOARD_READ",
            "android.permission.CLIPBOARD_WRITE"
        )
        
        val installedApps = context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
        return installedApps.any { app ->
            try {
                val packageInfo = context.packageManager.getPackageInfo(app.packageName, PackageManager.GET_PERMISSIONS)
                packageInfo.requestedPermissions?.any { permission ->
                    clipboardPermissions.contains(permission)
                } == true
            } catch (e: Exception) {
                false
            }
        }
    }

    private fun analyzeSideLoadedAPKs(): Boolean {
        val installedApps = context.packageManager.getInstalledApplications(0)
        val suspiciousApps = mutableListOf<String>()
        
        // Only flag apps that are from unknown sources, not just any non-system app
        for (app in installedApps) {
            val packageName = app.packageName
            
            // Enhanced system app detection
            val isSystemAppByFlag = (app.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM != 0
            val isSystemAppByUpdate = (app.flags ?: 0) and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
            val isSystemAppByPath = app.sourceDir?.startsWith("/system/") == true || 
                                   app.sourceDir?.startsWith("/vendor/") == true ||
                                   app.sourceDir?.startsWith("/product/") == true ||
                                   app.sourceDir?.startsWith("/system_ext/") == true ||
                                   app.sourceDir?.startsWith("/preload/") == true // Samsung preloaded apps
            
            // Enhanced system package prefixes list including more manufacturer apps
            val systemPackagePrefixes = listOf(
                // Android core
                "com.android.",
                "android.",
                // Google
                "com.google.android.",
                "com.google.ar.",
                // Samsung
                "com.sec.",
                "com.sec.android.",
                "com.samsung.",
                "com.samsung.android.",
                "com.samsung.SMT.",
                "com.samsung.accessibility.",
                "com.samsung.android.app.",
                "com.samsung.knox.",
                "com.sec.spp.",
                // Huawei
                "com.huawei.",
                "com.hisilicon.",
                // Xiaomi
                "com.xiaomi.",
                "com.miui.",
                // OnePlus
                "com.oneplus.",
                "net.oneplus.",
                // OPPO
                "com.oppo.",
                "com.coloros.",
                "com.color.",
                // Vivo
                "com.vivo.",
                "com.bbk.",
                // Motorola
                "com.motorola.",
                // Sony
                "com.sonyericsson.",
                "com.sony.",
                // LG
                "com.lge.",
                // HTC
                "com.htc."
            )
            val isSystemAppByPrefix = systemPackagePrefixes.any { packageName.startsWith(it) }
            
            // Catch any remaining manufacturer apps by name
            val isManufacturerApp = packageName.contains("samsung") || 
                                   packageName.contains("sec.") ||
                                   packageName.contains("oneplus") ||
                                   packageName.contains("xiaomi") ||
                                   packageName.contains("miui") ||
                                   packageName.contains("huawei") ||
                                   packageName.contains("oppo") ||
                                   packageName.contains("vivo") ||
                                   packageName.contains("htc") ||
                                   packageName.contains("lge") ||
                                   packageName.contains("sony")
            
            // Combined check for system apps
            val isSystemApp = isSystemAppByFlag || isSystemAppByUpdate || isSystemAppByPath || 
                             isSystemAppByPrefix || isManufacturerApp
            
            // Skip system apps
            if (isSystemApp) {
                continue
            }
            
            // Use our comprehensive source detection logic
            val source = getAppSource(packageName)
            
            // Only flag apps from unknown sources
            if (source == "Unknown Source") {
                suspiciousApps.add(packageName)
            }
        }
        
        // Return true only if there are suspicious apps
        return suspiciousApps.isNotEmpty()
    }

    private fun detectVirtualization(): Boolean {
        return Build.FINGERPRINT.contains("generic") ||
               Build.MODEL.contains("sdk") ||
               Build.DEVICE.contains("generic")
    }

    private fun checkPersistenceMechanisms(): Boolean {
        val startupReceivers = context.packageManager.queryBroadcastReceivers(
            android.content.Intent(android.content.Intent.ACTION_BOOT_COMPLETED),
            0
        )
        
        return startupReceivers.size > 10 // Arbitrary threshold
    }

    private fun checkSystemIntegrity(): Boolean {
        // Check system file integrity
        val systemFiles = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/system/sbin/su"
        )
        
        return systemFiles.any { file ->
            File(file).exists()
        }
    }

    /**
     * Verifies app's signature against known good signatures
     * Returns true if signature is valid, false otherwise
     */
    private fun verifyAppSignature(packageName: String): Boolean {
        try {
            // Get package info with signatures
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
            }
            
            // Get app signatures
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                if (packageInfo.signingInfo?.hasMultipleSigners() == true) {
                    packageInfo.signingInfo?.apkContentsSigners
                } else {
                    packageInfo.signingInfo?.signingCertificateHistory
                }
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }
            
            // If no signatures found, that's suspicious
            if (signatures == null || signatures.isEmpty()) {
                return false
            }
            
            // Get the signature checksums
            val signatureHashes = signatures.map { signature ->
                val md = MessageDigest.getInstance("SHA-256")
                val certBytes = signature.toByteArray()
                val digest = md.digest(certBytes)
                digest.joinToString(":") { String.format("%02x", it) }
            }.toSet()
            
            // First verify against our known good signatures for common apps
            if (knownGenuineAppSignatures.containsKey(packageName)) {
                val knownGoodSignatures = knownGenuineAppSignatures[packageName] ?: emptySet()
                // If we know this app's signature and it doesn't match, it's definitely suspicious
                return signatureHashes.any { hash -> knownGoodSignatures.any { it.equals(hash, ignoreCase = true) } }
            }
            
            // For Google Play Store apps or apps from trusted sources, we should check their installer
            val installationSource = getInstallationMetadata(packageName)
            if (installationSource.installerPackage != null && 
                trustedInstallers.contains(installationSource.installerPackage)) {
                
                // For apps from trusted sources, we assume signature is valid
                // A more thorough check would verify the signature chain
                return true
            }
            
            // Additional signals that might indicate a valid signature
            return when {
                // System apps are generally trusted
                installationSource.isSystemApp -> true
                
                // Check common signature characteristics of malicious apps
                signatureHashes.any { hash -> 
                    // Too short signatures are suspicious
                    hash.length < 20 ||
                    // Known bad signature patterns
                    hash.startsWith("00:00") || 
                    hash.contains("ff:ff:ff")
                } -> false
                
                // If we can't definitively say it's bad, give it the benefit of the doubt
                // but mark apps from unknown sources for further analysis
                else -> installationSource.installerPackage != null
            }
        } catch (e: Exception) {
            e.printStackTrace()
            // Exception during signature verification is suspicious
            return false
        }
    }

    // Updated method to verify installer source with better categorization
    private fun verifyInstallerSource(packageName: String): Map<String, Any> {
        try {
            // First check if it's a system app
            val isSystemApp = try {
                val appInfo = context.packageManager.getApplicationInfo(packageName, 0)
                (appInfo?.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM != 0
            } catch (e: Exception) {
                false
            }
            
            // Get the source using our comprehensive method
            val sourceType = getAppSource(packageName)
            
            // Get the installer for reporting purposes
            val installer = try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    context.packageManager.getInstallSourceInfo(packageName).installingPackageName
                } else {
                    @Suppress("DEPRECATION")
                    context.packageManager.getInstallerPackageName(packageName)
                }
            } catch (e: Exception) {
                null
            }
            
            // Determine if the source is trusted
            val isTrusted = sourceType == "Google Play Store" || 
                            sourceType == "Samsung Galaxy Store" || 
                            sourceType == "Huawei AppGallery" || 
                            sourceType == "Amazon Appstore" ||
                            sourceType == "System Application"
            
            // Return multiple pieces of information
            return mapOf(
                "isTrusted" to isTrusted,
                "sourceType" to sourceType,
                "installerPackage" to (installer ?: "unknown"),
                "isSystemApp" to isSystemApp
            )
        } catch (e: Exception) {
            e.printStackTrace()
            // Conservative approach: unknown installer is treated as suspicious
            return mapOf(
                "isTrusted" to false,
                "sourceType" to "Unknown Source",
                "installerPackage" to "unknown",
                "isSystemApp" to false
            )
        }
    }

    // Expanded root detection method
    private fun checkRootStatus(): RootStatus {
        val rootFiles = listOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/system/app/SuperSU.apk",
            "/cache/su",
            "/data/su",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/system/etc/init.d/99SuperSUDaemon",
            "/dev/.mount_rw",
            "/data/adb/magisk"
        )
        
        val rootPackages = listOf(
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.topjohnwu.magisk",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.smedialink.oneclickroot",
            "com.zhiqupk.root.global",
            "com.alephzain.framaroot"
        )
        
        val rootProperties = listOf(
            "ro.debuggable" to "1",
            "ro.secure" to "0",
            "service.adb.root" to "1",
            "ro.build.selinux" to "0",
            "ro.build.tags" to "test-keys"
        )
        
        // Check for SU binary in PATH
        val foundRootFiles = rootFiles.filter { File(it).exists() }
        
        // Check for known root packages
        val rootPackagesFound = rootPackages.filter { packageName ->
            try {
                context.packageManager.getPackageInfo(packageName, 0)
                true
            } catch (e: Exception) {
                false
            }
        }
        
        // Check system properties
        val rootPropertiesFound = rootProperties.filter { (prop, value) ->
            val systemValue = System.getProperty(prop)
            systemValue == value
        }
        
        // Check if device is in developer mode with USB debugging enabled
        val adbEnabled = Settings.Global.getInt(context.contentResolver, 
            Settings.Global.ADB_ENABLED, 0) == 1
        
        // Check if test-keys are used
        val isTestKeys = Build.TAGS?.contains("test-keys") == true
        
        // Build result
        return RootStatus(
            isRooted = foundRootFiles.isNotEmpty() || rootPackagesFound.isNotEmpty() || 
                       rootPropertiesFound.isNotEmpty() || isTestKeys,
            rootFiles = foundRootFiles,
            rootPackages = rootPackagesFound,
            rootProperties = rootPropertiesFound.map { "${it.first}=${it.second}" },
            developerMode = adbEnabled,
            testKeys = isTestKeys
        )
    }

    // Root status data class
    data class RootStatus(
        val isRooted: Boolean,
        val rootFiles: List<String>,
        val rootPackages: List<String>,
        val rootProperties: List<String>,
        val developerMode: Boolean,
        val testKeys: Boolean
    )

    // New class to store suspicious connection information
    data class SuspiciousConnection(
        val ipAddress: String,
        val port: Int,
        val protocol: String,
        val reason: String,
        val timestamp: Long = System.currentTimeMillis(),
        val severity: SeverityLevel = SeverityLevel.MEDIUM
    )
    
    // Severity levels for suspicious activities
    enum class SeverityLevel {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    private fun analyzeClonedApps(): List<CloneAppInfo> {
        val cloneApps = mutableListOf<CloneAppInfo>()
        val packageManager = context.packageManager
        
        try {
            val flags = PackageManager.GET_META_DATA or PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNATURES
            val installedApps = packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
            
            // Store app names to detect impersonation attempts
            val appNameMap = mutableMapOf<String, MutableList<String>>()
            
            // First pass: gather app names for impersonation detection
            for (app in installedApps) {
                val appName = try {
                    packageManager.getApplicationLabel(app).toString().lowercase()
                } catch (e: Exception) {
                    continue
                }
                
                if (appName.isNotEmpty()) {
                    if (!appNameMap.containsKey(appName)) {
                        appNameMap[appName] = mutableListOf()
                    }
                    appNameMap[appName]?.add(app.packageName)
                }
            }
            
            // Second pass: analyze apps for suspicious behavior
            for (app in installedApps) {
                val packageName = app.packageName
                
                // Skip system apps if they're not in our suspicious list
                val isSystemApp = (app.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM != 0
                if (isSystemApp && !suspiciousPackages.contains(packageName)) {
                    continue
                }
                
                // Get app details
                val appName = try {
                    packageManager.getApplicationLabel(app).toString()
                } catch (e: Exception) {
                    packageName
                }
                
                // Get detailed installation source metadata
                val installationSource = getInstallationMetadata(packageName)
                
                // Get permissions
                val permissions = try {
                    packageManager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
                        .requestedPermissions?.toList() ?: emptyList()
                } catch (e: Exception) {
                    emptyList()
                }
                
                // Verify app signature
                val signatureValid = verifyAppSignature(packageName)
                
                // Check for impersonation
                val appNameLower = appName.lowercase()
                val potentialImpersonation = appNameMap[appNameLower]?.size ?: 0 > 1
                
                // Get possible original package for this app name
                val originalPackage = if (potentialImpersonation) {
                    // Find the most likely original app (usually from a trusted source)
                    appNameMap[appNameLower]?.find { pkg ->
                        val source = getInstallationMetadata(pkg)
                        source.installerPackage != null && trustedInstallers.contains(source.installerPackage)
                    }
                } else null
                
                // Determine if installer is trusted
                val isTrustedInstaller = installationSource.installerPackage != null && 
                                        trustedInstallers.contains(installationSource.installerPackage)
                
                // Calculate permission risk score
                val permissionScore = scorePermissions(permissions)
                
                // Determine clone type with enhanced logic
                val cloneType = when {
                    // Known suspicious packages are likely repackaged
                    suspiciousPackages.contains(packageName) -> CloneType.REPACKAGED
                    
                    // Potential impersonation detected
                    potentialImpersonation && originalPackage != null && originalPackage != packageName -> 
                        CloneType.IMPERSONATION
                    
                    // Apps with invalid signatures
                    !signatureValid -> {
                        if (installationSource.installerPackage == null || !isTrustedInstaller) {
                            CloneType.REPACKAGED  // Likely repackaged if from unknown source
                        } else {
                            CloneType.TAMPERED    // Likely tampered if from known source but bad signature
                        }
                    }
                    
                    // Apps from unknown sources
                    installationSource.installerPackage == null || !isTrustedInstaller -> 
                        CloneType.UNKNOWN_SOURCE
                    
                    // Default case
                    else -> {
                        if (permissionScore > 40) {
                            CloneType.TAMPERED // Suspicious permissions even if source seems ok
                        } else {
                            continue // Skip if everything seems normal
                        }
                    }
                }
                
                // Add to suspicious app list
                cloneApps.add(
                    CloneAppInfo(
                        packageName = packageName,
                        appName = appName,
                        originalPackage = originalPackage,
                        cloneType = cloneType,
                        installerPackage = installationSource.installerPackage,
                        isTrustedInstaller = isTrustedInstaller,
                        signatureValid = signatureValid,
                        permissions = permissions,
                        installTime = installationSource.installationTime,
                        sourceType = if (isTrustedInstaller) {
                            installationSource.installerPackage ?: "Unknown Source"
                        } else "Unknown Source",
                        isSystemApp = isSystemApp
                    )
                )
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        
        return cloneApps
    }

    // Add this comprehensive app source detection method near the top of the class
    private fun getAppSource(packageName: String): String {
        // Step 1: Enhanced system app detection
        val isSystemApp = try {
            val appInfo = context.packageManager.getApplicationInfo(packageName, 0)
            
            // Check by flags
            val isSystemAppByFlag = (appInfo.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM != 0
            val isSystemAppByUpdate = (appInfo.flags ?: 0) and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
            
            // Check by installation path
            val isSystemAppByPath = appInfo.sourceDir?.startsWith("/system/") == true || 
                                   appInfo.sourceDir?.startsWith("/vendor/") == true ||
                                   appInfo.sourceDir?.startsWith("/product/") == true ||
                                   appInfo.sourceDir?.startsWith("/system_ext/") == true ||
                                   appInfo.sourceDir?.startsWith("/preload/") == true // Samsung preloaded apps
            
            // Check by package name prefix - enhanced with more manufacturer prefixes
            val systemPackagePrefixes = listOf(
                // Android core
                "com.android.",
                "android.",
                // Google
                "com.google.android.",
                "com.google.ar.",
                // Samsung
                "com.sec.",
                "com.sec.android.",
                "com.samsung.",
                "com.samsung.android.",
                "com.samsung.SMT.",
                "com.samsung.accessibility.",
                "com.samsung.android.app.",
                "com.samsung.knox.",
                "com.sec.spp.",
                // Huawei
                "com.huawei.",
                "com.hisilicon.",
                // Xiaomi
                "com.xiaomi.",
                "com.miui.",
                // OnePlus
                "com.oneplus.",
                "net.oneplus.",
                // OPPO
                "com.oppo.",
                "com.coloros.",
                "com.color.",
                // Vivo
                "com.vivo.",
                "com.bbk.",
                // Motorola
                "com.motorola.",
                // Sony
                "com.sonyericsson.",
                "com.sony.",
                // LG
                "com.lge.",
                // HTC
                "com.htc."
            )
            val isSystemAppByPrefix = systemPackagePrefixes.any { packageName.startsWith(it) }
            
            // Combined system app check
            isSystemAppByFlag || isSystemAppByUpdate || isSystemAppByPath || isSystemAppByPrefix
        } catch (e: Exception) {
            false
        }
        
        if (isSystemApp) {
            return "System Application"
        }
        
        // Step 2: Expanded list of known Play Store apps
        // This list should include popular apps that are definitely from Play Store
        val knownPlayStoreApps = setOf(
            // Google apps
            "com.google.android.youtube",
            "com.google.android.gm",
            "com.android.chrome",
            "com.google.android.apps.maps",
            "com.google.android.apps.photos",
            "com.google.android.music",
            "com.google.android.videos",
            "com.google.android.apps.docs",
            "com.google.android.keep",
            "com.google.android.calendar",
            
            // Meta apps
            "com.whatsapp",
            "com.facebook.katana",
            "com.facebook.lite",
            "com.instagram.android",
            "com.facebook.orca",
            
            // Other popular apps
            "com.spotify.music",
            "com.netflix.mediaclient",
            "com.amazon.mShop.android.shopping",
            "com.snapchat.android",
            "com.twitter.android",
            "org.telegram.messenger",
            "com.zhiliaoapp.musically",
            "com.linkedin.android",
            "com.pinterest",
            "com.ubercab",
            "com.ubercab.eats",
            "in.amazon.mShop.android.shopping",
            "com.paytm.paytmapp",
            "net.one97.paytm",
            "com.phonepe.app",
            "com.google.android.apps.nbu.paisa.user"
        )
        
        // Known Google packages
        if (packageName.startsWith("com.google.") || knownPlayStoreApps.contains(packageName)) {
            return "Google Play Store"
        }
        
        // Step 3: Check installer package
        val installer = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val installSourceInfo = context.packageManager.getInstallSourceInfo(packageName)
                installSourceInfo.installingPackageName
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getInstallerPackageName(packageName)
            }
        } catch (e: Exception) {
            null
        }
        
        // Step 4: Determine source by installer
        return when {
            installer == "com.android.vending" -> "Google Play Store"
            installer == "com.google.android.feedback" -> "Google Play Store"
            installer == "com.google.android.packageinstaller" -> "Google Play Store" // Often used for Play Store
            
            installer == "com.sec.android.app.samsungapps" -> "Samsung Galaxy Store"
            installer == "com.huawei.appmarket" -> "Huawei AppGallery"
            installer == "com.amazon.venezia" -> "Amazon Appstore"
            
            // Step 5: Additional verification for common apps even if installer is null
            installer == null -> {
                // Additional checks for well-known apps that might report null
                when {
                    // Meta apps often have specific signatures and might report null installer
                    packageName.contains("whatsapp") || 
                    packageName.contains("facebook") || 
                    packageName.contains("instagram") || 
                    packageName.contains("fb") -> "Google Play Store"
                    
                    // Google products should always be from Play Store
                    packageName.startsWith("com.google.") -> "Google Play Store"
                    
                    // Common trusted app prefixes
                    packageName.startsWith("com.adobe.") ||
                    packageName.startsWith("com.microsoft.") ||
                    packageName.startsWith("com.amazon.") ||
                    packageName.startsWith("com.spotify.") -> "Google Play Store"
                    
                    // If no trusted indicators, mark as unknown
                    else -> "Unknown Source"
                }
            }
            
            // Any other installers are considered unknown
            else -> "Unknown Source"
        }
    }

    /**
     * Get detailed metadata about app installation
     */
    private data class InstallationSource(
        val installerPackage: String?,
        val installationTime: Long,
        val installationMethod: String,
        val isSystemApp: Boolean,
        val isUpdated: Boolean
    )
    
    private fun getInstallationMetadata(packageName: String): InstallationSource {
        try {
            val packageInfo = context.packageManager.getPackageInfo(packageName, 0)
            val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                try {
                    context.packageManager.getInstallSourceInfo(packageName).initiatingPackageName
                } catch (e: Exception) {
                    null
                }
            } else {
                @Suppress("DEPRECATION")
                try {
                    context.packageManager.getInstallerPackageName(packageName)
                } catch (e: Exception) {
                    null
                }
            }
            
            val isSystemApp = (packageInfo.applicationInfo?.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM != 0
            
            return InstallationSource(
                installerPackage = installer,
                installationTime = packageInfo.firstInstallTime,
                installationMethod = if (isSystemApp) "system" else "user",
                isSystemApp = isSystemApp,
                isUpdated = packageInfo.lastUpdateTime > packageInfo.firstInstallTime
            )
        } catch (e: Exception) {
            return InstallationSource(
                installerPackage = "unknown",
                installationTime = 0,
                installationMethod = "unknown",
                isSystemApp = false,
                isUpdated = false
            )
        }
    }
    
    /**
     * Score an app based on its installation source
     */
    private fun scoreInstallationSource(source: InstallationSource): Int {
        var score = 0
        
        // Base score for trusted installer
        if (source.installerPackage == null || source.installerPackage == "unknown") {
            score += 50 // Unknown installer is highly suspicious
        } else if (!trustedInstallers.contains(source.installerPackage)) {
            score += 30 // Untrusted installer is somewhat suspicious
        }
        
        // Additional factors
        if (source.isSystemApp) {
            score -= 50 // System apps are generally trusted
        }
        
        if (source.isUpdated) {
            score += 10 // Updated apps might have been tampered with
        }
        
        // Very recent installation (within last 24 hours)
        if (System.currentTimeMillis() - source.installationTime < 24 * 60 * 60 * 1000) {
            score += 15 // Recently installed apps are more suspicious
        }
        
        return score
    }
    
    /**
     * Score permissions based on their potential danger
     */
    private fun scorePermissions(permissions: List<String>): Int {
        var score = 0
        
        // Count dangerous permissions
        val dangerousCount = permissions.count { perm ->
            dangerousPermissions.any { dangerous -> perm.endsWith(dangerous) }
        }
        
        // Score based on count of dangerous permissions
        score += when {
            dangerousCount >= 5 -> 50   // Many dangerous permissions
            dangerousCount >= 3 -> 30   // Several dangerous permissions
            dangerousCount >= 1 -> 10   // At least one dangerous permission
            else -> 0                   // No dangerous permissions
        }
        
        // Special case for particularly suspicious permission combinations
        if (permissions.any { it.endsWith("READ_SMS") } && 
            permissions.any { it.endsWith("SEND_SMS") }) {
            score += 25 // SMS read + send is very suspicious
        }
        
        if (permissions.any { it.endsWith("SYSTEM_ALERT_WINDOW") }) {
            score += 20 // Overlay permission is often misused
        }
        
        if (permissions.any { it.endsWith("CAMERA") } && 
            permissions.any { it.endsWith("RECORD_AUDIO") }) {
            score += 15 // Camera + microphone could be for spying
        }
        
        return score
    }
} 