package com.example.detection.service

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.PowerManager
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Auto-Heal Service
 * Provides self-defense capabilities for the honeypot system to automatically recover from
 * tampering attempts and protect sensitive components.
 */
class AutoHealService(private val context: Context) {

    companion object {
        private const val TAG = "AutoHealService"
        private const val PREFS_NAME = "auto_heal_secure_prefs"
        private const val KEY_INTEGRITY_CHECK_INTERVAL = "integrity_check_interval"
        private const val KEY_AUTO_RESTORE_ENABLED = "auto_restore_enabled"
        private const val KEY_COMPONENT_HASH_MAP = "component_hash_map"
        private const val KEY_BACKUP_INTERVAL = "backup_interval"
        private const val KEY_LAST_BACKUP_TIME = "last_backup_time"
        private const val KEY_HEAL_COUNTER = "heal_counter"
        private const val KEY_TAMPER_COUNTER = "tamper_counter"
        
        // Self-defense modes
        enum class DefenseMode {
            PASSIVE,      // Only monitor, no automatic actions
            REACTIVE,     // Automatically restore after confirmed tampering
            AGGRESSIVE    // Proactively protect and counter-attack tampering attempts
        }
        
        // Component types for integrity checks
        enum class ComponentType {
            PREFERENCE_FILE,
            DATABASE_FILE,
            CONFIG_FILE,
            TRAP_DEFINITION,
            SERVICE_COMPONENT,
            UI_COMPONENT
        }
    }
    
    // Master key alias for encryption
    private val masterKeyAlias by lazy {
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
    }
    
    // Encrypted shared preferences for secure settings
    private val securePrefs by lazy {
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKeyAlias,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }
    
    // Background scheduler for periodic tasks
    private val scheduler = Executors.newSingleThreadScheduledExecutor()
    
    // Current defense mode
    private var defenseMode = DefenseMode.REACTIVE
    
    // Monitoring state
    private val isMonitoring = AtomicBoolean(false)
    
    // Healing counters
    private val healCounter = AtomicInteger(0)
    private val tamperCounter = AtomicInteger(0)
    
    // Component integrity map - stores file paths and their expected hash values
    private val componentIntegrityMap = ConcurrentHashMap<String, ComponentInfo>()
    
    // Backup directory
    private val backupDir by lazy {
        File(context.filesDir, "honeypot_backups").apply {
            if (!exists()) {
                mkdirs()
            }
        }
    }
    
    // Gson instance for serialization
    private val gson = Gson()
    
    // Coroutine job for continuous monitoring
    private var monitoringJob: Job? = null
    
    init {
        loadSettings()
        loadIntegrityMap()
    }
    
    /**
     * Load service settings from secure storage
     */
    private fun loadSettings() {
        healCounter.set(securePrefs.getInt(KEY_HEAL_COUNTER, 0))
        tamperCounter.set(securePrefs.getInt(KEY_TAMPER_COUNTER, 0))
    }
    
    /**
     * Load component integrity map from secure storage
     */
    private fun loadIntegrityMap() {
        securePrefs.getString(KEY_COMPONENT_HASH_MAP, null)?.let { json ->
            try {
                val type = object : TypeToken<Map<String, ComponentInfo>>() {}.type
                val loadedMap: Map<String, ComponentInfo> = gson.fromJson(json, type)
                componentIntegrityMap.clear()
                componentIntegrityMap.putAll(loadedMap)
            } catch (e: Exception) {
                Log.e(TAG, "Error loading component integrity map: ${e.message}")
                // Initialize with default values if loading fails
                initializeDefaultIntegrityMap()
            }
        } ?: initializeDefaultIntegrityMap()
    }
    
    /**
     * Initialize default integrity map
     */
    private fun initializeDefaultIntegrityMap() {
        componentIntegrityMap.clear()
        
        // Add honeypot shared preferences file
        val prefsFile = File(context.applicationInfo?.dataDir ?: context.filesDir.absolutePath, "shared_prefs/honeypot_preferences.xml")
        if (prefsFile.exists()) {
            val hash = calculateFileHash(prefsFile)
            componentIntegrityMap[prefsFile.absolutePath] = ComponentInfo(
                path = prefsFile.absolutePath,
                expectedHash = hash,
                type = ComponentType.PREFERENCE_FILE,
                lastVerified = System.currentTimeMillis(),
                backupPath = createBackup(prefsFile)
            )
        }
        
        // Add honeypot database file
        val dbFile = context.getDatabasePath("honeypot_db")
        if (dbFile.exists()) {
            val hash = calculateFileHash(dbFile)
            componentIntegrityMap[dbFile.absolutePath] = ComponentInfo(
                path = dbFile.absolutePath,
                expectedHash = hash,
                type = ComponentType.DATABASE_FILE,
                lastVerified = System.currentTimeMillis(),
                backupPath = createBackup(dbFile)
            )
        }
        
        // Save the integrity map
        saveIntegrityMap()
    }
    
    /**
     * Save integrity map to secure storage
     */
    private fun saveIntegrityMap() {
        try {
            val json = gson.toJson(componentIntegrityMap)
            securePrefs.edit().putString(KEY_COMPONENT_HASH_MAP, json).apply()
        } catch (e: Exception) {
            Log.e(TAG, "Error saving component integrity map: ${e.message}")
        }
    }
    
    /**
     * Start the auto-heal monitoring service
     * @param intervalMinutes How often to check component integrity (in minutes)
     */
    fun startMonitoring(intervalMinutes: Int = 15) {
        if (isMonitoring.compareAndSet(false, true)) {
            securePrefs.edit().putInt(KEY_INTEGRITY_CHECK_INTERVAL, intervalMinutes).apply()
            
            // Schedule periodic integrity checks
            scheduler.scheduleAtFixedRate({
                try {
                    performIntegrityCheck()
                } catch (e: Exception) {
                    Log.e(TAG, "Error during scheduled integrity check: ${e.message}")
                }
            }, intervalMinutes.toLong(), intervalMinutes.toLong(), TimeUnit.MINUTES)
            
            // Start continuous monitoring in a coroutine
            monitoringJob = CoroutineScope(Dispatchers.IO).launch {
                while (isActive) {
                    try {
                        monitorSystemHealth()
                        delay(30_000) // Check every 30 seconds
                    } catch (e: Exception) {
                        Log.e(TAG, "Error during continuous monitoring: ${e.message}")
                        delay(60_000) // Delay longer if there was an error
                    }
                }
            }
            
            Log.d(TAG, "Auto-heal monitoring started with interval: $intervalMinutes minutes")
        }
    }
    
    /**
     * Stop the auto-heal monitoring service
     */
    fun stopMonitoring() {
        if (isMonitoring.compareAndSet(true, false)) {
            scheduler.shutdown()
            monitoringJob?.cancel()
            monitoringJob = null
            Log.d(TAG, "Auto-heal monitoring stopped")
        }
    }
    
    /**
     * Set the defense mode
     */
    fun setDefenseMode(mode: DefenseMode) {
        this.defenseMode = mode
        Log.d(TAG, "Defense mode set to: $mode")
    }
    
    /**
     * Get the current defense mode
     */
    fun getDefenseMode(): DefenseMode {
        return defenseMode
    }
    
    /**
     * Get heal counter
     */
    fun getHealCounter(): Int {
        return healCounter.get()
    }
    
    /**
     * Get tamper counter
     */
    fun getTamperCounter(): Int {
        return tamperCounter.get()
    }
    
    /**
     * Register a component for integrity monitoring
     */
    fun registerComponent(path: String, type: ComponentType): Boolean {
        val file = File(path)
        if (!file.exists()) {
            Log.e(TAG, "Cannot register non-existent component: $path")
            return false
        }
        
        try {
            val hash = calculateFileHash(file)
            val backupPath = createBackup(file)
            
            componentIntegrityMap[path] = ComponentInfo(
                path = path,
                expectedHash = hash,
                type = type,
                lastVerified = System.currentTimeMillis(),
                backupPath = backupPath
            )
            
            saveIntegrityMap()
            Log.d(TAG, "Component registered for integrity monitoring: $path")
            return true
        } catch (e: Exception) {
            Log.e(TAG, "Error registering component: ${e.message}")
            return false
        }
    }
    
    /**
     * Unregister a component from integrity monitoring
     */
    fun unregisterComponent(path: String): Boolean {
        val removed = componentIntegrityMap.remove(path)
        if (removed != null) {
            saveIntegrityMap()
            Log.d(TAG, "Component unregistered from integrity monitoring: $path")
            return true
        }
        return false
    }
    
    /**
     * Create a backup of a file
     */
    private fun createBackup(file: File): String {
        try {
            val backupFile = File(backupDir, "${file.name}.backup")
            file.copyTo(backupFile, overwrite = true)
            securePrefs.edit().putLong(KEY_LAST_BACKUP_TIME, System.currentTimeMillis()).apply()
            Log.d(TAG, "Created backup of ${file.name} at ${backupFile.absolutePath}")
            return backupFile.absolutePath
        } catch (e: Exception) {
            Log.e(TAG, "Error creating backup: ${e.message}")
            return ""
        }
    }
    
    /**
     * Restore a component from backup
     */
    private fun restoreFromBackup(path: String): Boolean {
        val componentInfo = componentIntegrityMap[path] ?: return false
        
        if (componentInfo.backupPath.isEmpty()) {
            Log.e(TAG, "No backup available for component: $path")
            return false
        }
        
        try {
            val backupFile = File(componentInfo.backupPath)
            if (!backupFile.exists()) {
                Log.e(TAG, "Backup file does not exist: ${componentInfo.backupPath}")
                return false
            }
            
            val targetFile = File(path)
            backupFile.copyTo(targetFile, overwrite = true)
            
            // Update the hash after restoration
            val newHash = calculateFileHash(targetFile)
            componentIntegrityMap[path] = componentInfo.copy(
                expectedHash = newHash,
                lastVerified = System.currentTimeMillis()
            )
            
            saveIntegrityMap()
            
            // Increment heal counter
            val count = healCounter.incrementAndGet()
            securePrefs.edit().putInt(KEY_HEAL_COUNTER, count).apply()
            
            Log.d(TAG, "Successfully restored component from backup: $path")
            
            return true
        } catch (e: Exception) {
            Log.e(TAG, "Error restoring from backup: ${e.message}")
            return false
        }
    }
    
    /**
     * Perform integrity check on all registered components
     */
    fun performIntegrityCheck(): List<IntegrityCheckResult> {
        val results = mutableListOf<IntegrityCheckResult>()
        
        for ((path, info) in componentIntegrityMap) {
            val file = File(path)
            
            if (!file.exists()) {
                // File missing - definite tampering!
                val restored = if (defenseMode != DefenseMode.PASSIVE) {
                    restoreFromBackup(path)
                } else false
                
                results.add(
                    IntegrityCheckResult(
                        path = path,
                        type = info.type,
                        status = IntegrityStatus.MISSING,
                        wasRestored = restored,
                        timestamp = System.currentTimeMillis()
                    )
                )
                
                tamperCounter.incrementAndGet()
                securePrefs.edit().putInt(KEY_TAMPER_COUNTER, tamperCounter.get()).apply()
                
                continue
            }
            
            try {
                val currentHash = calculateFileHash(file)
                
                if (currentHash != info.expectedHash) {
                    // Hash mismatch - potential tampering
                    val restored = if (defenseMode != DefenseMode.PASSIVE) {
                        restoreFromBackup(path)
                    } else false
                    
                    results.add(
                        IntegrityCheckResult(
                            path = path,
                            type = info.type,
                            status = IntegrityStatus.MODIFIED,
                            wasRestored = restored,
                            timestamp = System.currentTimeMillis()
                        )
                    )
                    
                    tamperCounter.incrementAndGet()
                    securePrefs.edit().putInt(KEY_TAMPER_COUNTER, tamperCounter.get()).apply()
                } else {
                    // Hash match - integrity confirmed
                    results.add(
                        IntegrityCheckResult(
                            path = path,
                            type = info.type,
                            status = IntegrityStatus.INTACT,
                            wasRestored = false,
                            timestamp = System.currentTimeMillis()
                        )
                    )
                    
                    // Update last verified time
                    componentIntegrityMap[path] = info.copy(
                        lastVerified = System.currentTimeMillis()
                    )
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error checking integrity of $path: ${e.message}")
                results.add(
                    IntegrityCheckResult(
                        path = path,
                        type = info.type,
                        status = IntegrityStatus.ERROR,
                        wasRestored = false,
                        timestamp = System.currentTimeMillis()
                    )
                )
            }
        }
        
        // Save updated integrity map
        saveIntegrityMap()
        
        // Broadcast results if any tampering was detected
        val tamperingDetected = results.any { it.status != IntegrityStatus.INTACT }
        if (tamperingDetected) {
            val intent = Intent("com.example.detection.TAMPERING_DETECTED")
            intent.putExtra("results_count", results.size)
            intent.putExtra("timestamp", System.currentTimeMillis())
            context.sendBroadcast(intent)
        }
        
        return results
    }
    
    /**
     * Calculate file hash
     */
    private fun calculateFileHash(file: File): String {
        return try {
            val bytes = file.readBytes()
            val md = java.security.MessageDigest.getInstance("SHA-256")
            val digest = md.digest(bytes)
            digest.fold("") { str, it -> str + "%02x".format(it) }
        } catch (e: IOException) {
            Log.e(TAG, "Error calculating file hash: ${e.message}")
            ""
        }
    }
    
    /**
     * Monitor system health
     */
    private suspend fun monitorSystemHealth() {
        withContext(Dispatchers.IO) {
            // Check if our process is still running with expected permissions
            val pm = context.packageManager
            try {
                val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(context.packageName, PackageManager.PackageInfoFlags.of(0))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(context.packageName, 0)
                }
                
                if (packageInfo.applicationInfo?.enabled == true) {
                    // App is enabled, all good
                } else {
                    // App has been disabled - potential tampering
                    Log.w(TAG, "Application has been disabled - possible tampering attempt")
                    
                    if (defenseMode == DefenseMode.AGGRESSIVE) {
                        // In aggressive mode, try to re-enable ourselves
                        // Note: This requires device admin privileges and may not work on all devices
                        attemptSelfProtection()
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error checking package info: ${e.message}")
            }
            
            // Check for battery optimization exemption
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val powerManager = context.getSystemService(Context.POWER_SERVICE) as PowerManager
                if (!powerManager.isIgnoringBatteryOptimizations(context.packageName)) {
                    // We're not exempted from battery optimizations
                    // This could affect our monitoring capabilities
                    Log.w(TAG, "Not exempted from battery optimizations - monitoring may be limited")
                }
            }
            
            // Check storage state
            val freeSpace = backupDir.freeSpace
            if (freeSpace < 10 * 1024 * 1024) { // Less than 10MB free
                Log.w(TAG, "Low storage space for backups: ${freeSpace / (1024 * 1024)}MB")
                
                // Clean up old backups if needed
                cleanupOldBackups()
            }
        }
    }
    
    /**
     * Clean up old backups to free space
     */
    private fun cleanupOldBackups() {
        val maxBackupsToKeep = 3
        
        // Group backups by component
        val backupsByComponent = backupDir.listFiles()
            ?.filter { it.name.endsWith(".backup") }
            ?.groupBy { it.name.substringBefore(".backup") }
            
        backupsByComponent?.forEach { (component, files) ->
            if (files.size > maxBackupsToKeep) {
                // Keep only the newest backups
                files.sortedBy { it.lastModified() }
                    .dropLast(maxBackupsToKeep)
                    .forEach { it.delete() }
            }
        }
    }
    
    /**
     * Attempt self-protection measures
     * Note: Many of these actions require system permissions and may not work on all devices
     */
    private fun attemptSelfProtection() {
        // This is a placeholder for advanced self-protection measures
        // Real implementation would depend on available permissions and device capabilities
        Log.d(TAG, "Attempting self-protection measures")
        
        // Example: could try to re-launch main activity
        try {
            val intent = context.packageManager.getLaunchIntentForPackage(context.packageName)
            intent?.let {
                it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(it)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error launching main activity: ${e.message}")
        }
    }
    
    /**
     * Get integrity check statistics
     */
    fun getIntegrityStats(): IntegrityStatistics {
        return IntegrityStatistics(
            totalComponents = componentIntegrityMap.size,
            healCount = healCounter.get(),
            tamperCount = tamperCounter.get(),
            lastBackupTime = securePrefs.getLong(KEY_LAST_BACKUP_TIME, 0),
            defenseMode = defenseMode,
            componentTypes = componentIntegrityMap.values.groupBy { it.type }
                .mapValues { it.value.size }
        )
    }
    
    /**
     * Data class for component integrity information
     */
    data class ComponentInfo(
        val path: String,
        val expectedHash: String,
        val type: ComponentType,
        val lastVerified: Long,
        val backupPath: String
    )
    
    /**
     * Enumeration for integrity check status
     */
    enum class IntegrityStatus {
        INTACT,     // Component matches expected hash
        MODIFIED,   // Component has been modified
        MISSING,    // Component is missing
        ERROR       // Error checking component
    }
    
    /**
     * Data class for integrity check results
     */
    data class IntegrityCheckResult(
        val path: String,
        val type: ComponentType,
        val status: IntegrityStatus,
        val wasRestored: Boolean,
        val timestamp: Long
    )
    
    /**
     * Data class for integrity statistics
     */
    data class IntegrityStatistics(
        val totalComponents: Int,
        val healCount: Int,
        val tamperCount: Int,
        val lastBackupTime: Long,
        val defenseMode: DefenseMode,
        val componentTypes: Map<ComponentType, Int>
    )
} 