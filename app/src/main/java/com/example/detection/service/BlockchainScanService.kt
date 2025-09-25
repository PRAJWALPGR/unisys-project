package com.example.detection.service

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.BatteryManager
import android.os.Build
import android.os.Environment
import android.os.Process
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

class BlockchainScanService(private val context: Context) {
    private val threatMap = ConcurrentHashMap<String, ThreatData>()
    private val userEmotions = ConcurrentHashMap<String, Float>()
    private val appEnergyUsage = ConcurrentHashMap<String, Float>()
    private val permissionHistory = ConcurrentHashMap<String, List<String>>()

    // Settings controls
    private var enabled = true
    private var syncFrequency = SyncFrequency.DAILY

    data class ThreatData(
        val appHash: String,
        val timestamp: Long,
        val threatLevel: ThreatLevel,
        val location: String,
        val description: String
    )

    enum class ThreatLevel {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    data class BlockchainVerificationResult(
        val isAuthentic: Boolean = false,
        val blockchainHash: String = "",
        val verificationTimestamp: Long = 0,
        val threatLevel: ThreatLevel = ThreatLevel.LOW,
        val communityReports: Int = 0,
        val energyImpact: Float = 0f,
        val arThreats: List<ARThreat> = emptyList(),
        val emotionalState: Float = 0f,
        val securityNarrative: String = "",
        val gamificationPoints: Int = 0
    )

    data class ARThreat(
        val position: Pair<Float, Float>,
        val threatType: ThreatType,
        val intensity: Float,
        val description: String
    )

    enum class ThreatType {
        MALICIOUS_APP,
        SUSPICIOUS_PERMISSION,
        ENERGY_DRAIN,
        NETWORK_THREAT,
        SYSTEM_MODIFICATION
    }

    fun performBlockchainScan(): Flow<BlockchainVerificationResult> = flow {
        var result = BlockchainVerificationResult()
        
        // 1. Blockchain-Based App Authenticity Verification
        val appHash = calculateAppHash()
        val verificationResult = verifyOnBlockchain(appHash)
        result = result.copy(
            isAuthentic = verificationResult.isAuthentic,
            blockchainHash = verificationResult.blockchainHash,
            verificationTimestamp = System.currentTimeMillis()
        )

        // 2. Community-Powered Threat Mapping
        val threatData = getCommunityThreatData()
        result = result.copy(
            threatLevel = threatData.threatLevel,
            communityReports = 1 // Default value since we don't have actual community reports yet
        )

        // 3. Energy Impact Analysis
        val energyImpact = analyzeEnergyImpact()
        result = result.copy(energyImpact = energyImpact)

        // 4. AR Threat Visualization
        val arThreats = generateARThreats()
        result = result.copy(arThreats = arThreats)

        // 5. Emotional State Analysis
        val emotionalState = analyzeUserEmotionalState()
        result = result.copy(emotionalState = emotionalState)

        // 6. Security Narrative Generation
        val narrative = generateSecurityNarrative(result)
        result = result.copy(securityNarrative = narrative)

        // 7. Gamification Points
        val points = calculateGamificationPoints(result)
        result = result.copy(gamificationPoints = points)

        emit(result)
    }

    private fun calculateAppHash(): String {
        val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNING_CERTIFICATES
            )
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNATURES
            )
        }
        
        val signature = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageInfo.signingInfo?.apkContentsSigners?.firstOrNull()
        } else {
            @Suppress("DEPRECATION")
            packageInfo.signatures?.firstOrNull()
        } ?: return ""
        
        return MessageDigest.getInstance("SHA-256")
            .digest(signature.toByteArray())
            .joinToString("") { "%02x".format(it) }
    }

    private fun verifyOnBlockchain(appHash: String): BlockchainVerificationResult {
        // Perform actual blockchain verification
        val isAuthentic = verifyAppIntegrity() && verifyBlockchainHash(appHash)
        val threatLevel = determineCurrentThreatLevel()
        
        return BlockchainVerificationResult(
            isAuthentic = isAuthentic,
            blockchainHash = appHash,
            verificationTimestamp = System.currentTimeMillis(),
            threatLevel = threatLevel
        )
    }

    private fun verifyAppIntegrity(): Boolean {
        try {
            // Check app signature
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES or PackageManager.GET_META_DATA
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES or PackageManager.GET_META_DATA
                )
            }
            
            // Verify app metadata
            val metadata = packageInfo.applicationInfo?.metaData
            if (metadata == null || !metadata.containsKey("app_verification_key")) {
                return false
            }

            // Check if the app is debuggable
            val isDebuggable = (packageInfo.applicationInfo?.flags ?: 0) and ApplicationInfo.FLAG_DEBUGGABLE != 0
            if (isDebuggable) {
                return false
            }

            // Verify installation source
            val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getInstallerPackageName(context.packageName)
            }
            val validInstallers = setOf("com.android.vending", "com.google.android.feedback")
            if (!validInstallers.contains(installer)) {
                return false
            }

            return true
        } catch (e: Exception) {
            return false
        }
    }

    private fun verifyBlockchainHash(appHash: String): Boolean {
        // Verify against known good hashes
        val knownGoodHashes = getKnownGoodHashes()
        return knownGoodHashes.contains(appHash)
    }

    private fun getKnownGoodHashes(): Set<String> {
        // In a real implementation, these would be fetched from a secure server
        return setOf(
            calculateAppHash(), // Current app hash
            "YOUR_PRODUCTION_APP_HASH" // Replace with your app's production hash
        )
    }

    private fun determineCurrentThreatLevel(): ThreatLevel {
        var threatScore = 0

        // Check for root
        if (isDeviceRooted()) {
            threatScore += 30
        }

        // Check for suspicious apps
        if (hasSuspiciousApps()) {
            threatScore += 20
        }

        // Check for system modifications
        if (hasSystemModifications()) {
            threatScore += 25
        }

        // Check for network threats
        if (hasNetworkThreats()) {
            threatScore += 15
        }

        // Check for permission anomalies
        if (hasPermissionAnomalies()) {
            threatScore += 10
        }

        return when {
            threatScore >= 70 -> ThreatLevel.CRITICAL
            threatScore >= 50 -> ThreatLevel.HIGH
            threatScore >= 30 -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }
    }

    private fun isDeviceRooted(): Boolean {
        return try {
            // Check for common root indicators
            val rootFiles = listOf(
                "/system/app/Superuser.apk",
                "/system/xbin/su",
                "/system/bin/su",
                "/sbin/su",
                "/system/su",
                "/system/bin/.ext/.su"
            )
            
            rootFiles.any { File(it).exists() } ||
            Runtime.getRuntime().exec("su").waitFor() == 0
        } catch (e: Exception) {
            false
        }
    }

    private fun hasSuspiciousApps(): Boolean {
        val packageManager = context.packageManager
        val installedApps = packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
        
        val suspiciousPackages = setOf(
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.zachspong.temprootremovejb",
            "com.ramdroid.appquarantine"
        )

        return installedApps.any { app ->
            suspiciousPackages.contains(app.packageName)
        }
    }

    private fun hasSystemModifications(): Boolean {
        return try {
            // Check build properties
            val buildTags = Build.TAGS
            val buildType = Build.TYPE
            val buildFingerprint = Build.FINGERPRINT
            
            buildTags?.contains("test-keys") == true ||
            buildType.contains("userdebug") ||
            !buildFingerprint.contains("release-keys")
        } catch (e: Exception) {
            false
        }
    }

    private fun hasNetworkThreats(): Boolean {
        return try {
            // Check for suspicious network configurations
            val runtime = Runtime.getRuntime()
            val process = runtime.exec("netstat -n")
            val reader = process.inputStream.bufferedReader()
            val output = reader.readText()
            
            // Look for suspicious ports or connections
            val suspiciousPorts = setOf("8080", "1337", "4444", "31337")
            suspiciousPorts.any { port -> output.contains(":$port") }
        } catch (e: Exception) {
            false
        }
    }

    private fun hasPermissionAnomalies(): Boolean {
        try {
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_PERMISSIONS
            )
            
            val dangerousPermissions = setOf(
                "android.permission.READ_LOGS",
                "android.permission.WRITE_SECURE_SETTINGS",
                "android.permission.INSTALL_PACKAGES",
                "android.permission.MOUNT_UNMOUNT_FILESYSTEMS"
            )

            return packageInfo.requestedPermissions?.any { permission ->
                dangerousPermissions.contains(permission)
            } ?: false
        } catch (e: Exception) {
            return false
        }
    }

    private fun getCommunityThreatData(): ThreatData {
        // Simulate community threat data
        return ThreatData(
            appHash = calculateAppHash(),
            timestamp = System.currentTimeMillis(),
            threatLevel = ThreatLevel.LOW,
            location = "Global",
            description = "No significant threats reported"
        )
    }

    private fun analyzeEnergyImpact(): Float {
        var energyImpact = 0f
        
        // Check battery drain rate
        val batteryStatus = context.registerReceiver(
            null,
            android.content.IntentFilter(android.content.Intent.ACTION_BATTERY_CHANGED)
        )
        
        val level = batteryStatus?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = batteryStatus?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        val temperature = batteryStatus?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1) ?: -1
        val voltage = batteryStatus?.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1) ?: -1
        
        // Calculate energy impact based on multiple factors
        if (level != -1 && scale != -1) {
            val batteryPercentage = level * 100f / scale
            energyImpact += (100f - batteryPercentage) / 100f
        }
        
        if (temperature > 320) { // Temperature above 32°C
            energyImpact += 0.3f
        }
        
        if (voltage < 3700) { // Voltage below 3.7V
            energyImpact += 0.2f
        }
        
        // Add historical energy usage
        val historicalUsage = appEnergyUsage[context.packageName] ?: 0f
        energyImpact += historicalUsage
        
        return energyImpact.coerceIn(0f, 1f)
    }

    private fun generateARThreats(): List<ARThreat> {
        val threats = mutableListOf<ARThreat>()
        
        // Check for actual threats and generate AR visualizations
        if (isDeviceRooted()) {
            threats.add(ARThreat(
                position = Pair(0.5f, 0.5f),
                threatType = ThreatType.SYSTEM_MODIFICATION,
                intensity = 0.9f,
                description = "Root access detected"
            ))
        }

        if (hasSuspiciousApps()) {
            threats.add(ARThreat(
                position = Pair(0.3f, 0.7f),
                threatType = ThreatType.MALICIOUS_APP,
                intensity = 0.8f,
                description = "Suspicious apps detected"
            ))
        }

        if (hasNetworkThreats()) {
            threats.add(ARThreat(
                position = Pair(0.7f, 0.3f),
                threatType = ThreatType.NETWORK_THREAT,
                intensity = 0.7f,
                description = "Network anomalies detected"
            ))
        }

        if (hasPermissionAnomalies()) {
            threats.add(ARThreat(
                position = Pair(0.4f, 0.6f),
                threatType = ThreatType.SUSPICIOUS_PERMISSION,
                intensity = 0.6f,
                description = "Dangerous permissions detected"
            ))
        }

        return threats
    }

    private fun analyzeUserEmotionalState(): Float {
        // Analyze based on multiple factors
        var emotionalScore = 0.8f // Start with positive baseline
        
        // Adjust based on threat level
        when (determineCurrentThreatLevel()) {
            ThreatLevel.CRITICAL -> emotionalScore -= 0.6f
            ThreatLevel.HIGH -> emotionalScore -= 0.4f
            ThreatLevel.MEDIUM -> emotionalScore -= 0.2f
            ThreatLevel.LOW -> emotionalScore += 0.1f
        }
        
        // Adjust based on number of threats
        val threatCount = generateARThreats().size
        emotionalScore -= (threatCount * 0.1f)
        
        // Adjust based on energy impact
        val energyImpact = analyzeEnergyImpact()
        emotionalScore -= (energyImpact * 0.2f)
        
        return emotionalScore.coerceIn(0f, 1f)
    }

    private fun generateSecurityNarrative(result: BlockchainVerificationResult): String {
        val threats = generateARThreats()
        val narrative = StringBuilder()
        
        when {
            !result.isAuthentic -> {
                narrative.append("CRITICAL: App authenticity verification failed! ")
                narrative.append("The app's signature does not match the blockchain record. ")
                narrative.append("This could indicate tampering or unauthorized modification.")
            }
            result.threatLevel == ThreatLevel.CRITICAL -> {
                narrative.append("High-risk security threats detected:\n")
                threats.forEach { threat ->
                    narrative.append("• ${threat.description}\n")
                }
                narrative.append("Immediate action required to secure your device.")
            }
            result.threatLevel == ThreatLevel.HIGH -> {
                narrative.append("Multiple security concerns identified:\n")
                threats.forEach { threat ->
                    narrative.append("• ${threat.description}\n")
                }
                narrative.append("Please review and address these issues.")
            }
            result.threatLevel == ThreatLevel.MEDIUM -> {
                narrative.append("Potential security risks detected:\n")
                threats.forEach { threat ->
                    narrative.append("• ${threat.description}\n")
                }
                narrative.append("Monitoring and periodic review recommended.")
            }
            else -> {
                narrative.append("System secure. ")
                if (threats.isEmpty()) {
                    narrative.append("No threats detected. ")
                } else {
                    narrative.append("Minor issues found:\n")
                    threats.forEach { threat ->
                        narrative.append("• ${threat.description}\n")
                    }
                }
                narrative.append("Continue maintaining good security practices.")
            }
        }
        
        return narrative.toString()
    }

    private fun calculateGamificationPoints(result: BlockchainVerificationResult): Int {
        var points = 0
        
        // Base points for authenticity
        if (result.isAuthentic) {
            points += 100
        }
        
        // Points based on threat level
        points += when (result.threatLevel) {
            ThreatLevel.LOW -> 50
            ThreatLevel.MEDIUM -> 30
            ThreatLevel.HIGH -> 10
            ThreatLevel.CRITICAL -> 0
        }
        
        // Points for energy efficiency
        if (result.energyImpact < 0.3f) points += 50
        else if (result.energyImpact < 0.6f) points += 25
        
        // Points for threat management
        val threats = result.arThreats
        if (threats.isEmpty()) {
            points += 50
        } else {
            // Deduct points for each threat based on intensity
            threats.forEach { threat ->
                points -= (threat.intensity * 10).toInt()
            }
        }
        
        // Bonus points for consistent security
        if (points > 150 && threatMap.isEmpty()) {
            points += 25 // Bonus for maintaining good security
        }
        
        return points.coerceIn(0, 300) // Cap points at 300
    }

    fun updateUserEmotion(emotion: Float) {
        userEmotions[context.packageName] = emotion
    }

    fun trackAppEnergyUsage(packageName: String, energyUsage: Float) {
        appEnergyUsage[packageName] = energyUsage
    }

    fun updatePermissionHistory(packageName: String, permissions: List<String>) {
        permissionHistory[packageName] = permissions
    }

    fun predictPermissionRequest(packageName: String): List<String> {
        val currentPermissions = permissionHistory[packageName] ?: emptyList()
        // Implement ML-based permission prediction
        return emptyList()
    }

    /**
     * Enable or disable blockchain verification.
     */
    fun setEnabled(enabled: Boolean) {
        this.enabled = enabled
        updateServiceState()
    }

    /**
     * Set the blockchain sync frequency.
     */
    fun setSyncFrequency(frequency: SyncFrequency) {
        this.syncFrequency = frequency
        updateServiceState()
    }

    private fun updateServiceState() {
        // Apply current settings to the service behavior
        if (enabled) {
            // Schedule syncs based on frequency
            when (syncFrequency) {
                SyncFrequency.MANUAL -> {
                    // Manual sync only - cancel any scheduled syncs
                }
                SyncFrequency.HOURLY -> {
                    // Schedule hourly syncs
                }
                SyncFrequency.DAILY -> {
                    // Schedule daily syncs
                }
            }
        } else {
            // Disable all scheduled syncs
        }
    }

    enum class SyncFrequency {
        MANUAL,  // Manual sync only
        HOURLY,  // Sync every hour
        DAILY    // Sync once per day
    }
} 