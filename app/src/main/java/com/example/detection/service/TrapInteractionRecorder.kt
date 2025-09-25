package com.example.detection.service

import android.content.Context
import android.util.Log
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKeys
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import java.io.File
import java.io.FileOutputStream
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Trap Interaction Recorder
 * Records detailed metadata about trap interactions for forensic analysis and replay
 */
class TrapInteractionRecorder(private val context: Context) {

    private val TAG = "TrapInteractionRecorder"
    
    // Store interaction sequences by trap ID
    private val interactionRecords = ConcurrentHashMap<String, MutableList<TrapInteraction>>()
    
    // Maximum interactions to keep in memory per trap
    private val MAX_MEMORY_INTERACTIONS = 50
    
    // Gson for JSON serialization/deserialization
    private val gson: Gson = GsonBuilder()
        .setPrettyPrinting()
        .setDateFormat("yyyy-MM-dd HH:mm:ss.SSS")
        .create()
    
    // Date formatter for filenames
    private val dateFormat = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US)
    
    // Create a master key for encryption
    private val masterKeyAlias by lazy {
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
    }
    
    /**
     * Record a trap interaction event
     */
    fun recordInteraction(
        trapId: String,
        trapType: CloneDetectionService.TrapType,
        trapName: String,
        action: InteractionType,
        packageName: String? = null,
        stackTrace: Array<StackTraceElement>? = null,
        metadata: Map<String, Any>? = null
    ) {
        // Create the interaction record
        val interaction = TrapInteraction(
            id = UUID.randomUUID().toString(),
            trapId = trapId,
            trapType = trapType.name,
            trapName = trapName,
            timestamp = System.currentTimeMillis(),
            interactionType = action,
            packageName = packageName ?: "unknown",
            stackTrace = stackTrace?.joinToString("\n") { it.toString() },
            metadata = metadata ?: emptyMap()
        )
        
        // Add to memory cache
        val interactions = interactionRecords.getOrPut(trapId) { mutableListOf() }
        interactions.add(interaction)
        
        // Trim if too many
        if (interactions.size > MAX_MEMORY_INTERACTIONS) {
            val excess = interactions.size - MAX_MEMORY_INTERACTIONS
            repeat(excess) {
                interactions.removeAt(0)
            }
        }
        
        // Asynchronously save to disk
        Thread {
            try {
                saveInteractionToDisk(trapId, interaction)
            } catch (e: Exception) {
                Log.e(TAG, "Error saving interaction to disk: ${e.message}")
            }
        }.start()
    }
    
    /**
     * Record file interaction with more details
     */
    fun recordFileInteraction(
        trapId: String,
        trapName: String,
        filePath: String,
        accessType: String,
        packageName: String? = null
    ) {
        val metadata = mapOf(
            "filePath" to filePath,
            "accessType" to accessType,
            "deviceModel" to android.os.Build.MODEL,
            "androidVersion" to android.os.Build.VERSION.RELEASE
        )
        
        recordInteraction(
            trapId = trapId,
            trapType = CloneDetectionService.TrapType.FILE,
            trapName = trapName,
            action = InteractionType.FILE_ACCESS,
            packageName = packageName,
            stackTrace = Thread.currentThread().stackTrace,
            metadata = metadata
        )
    }
    
    /**
     * Record network interaction with more details
     */
    fun recordNetworkInteraction(
        trapId: String,
        trapName: String,
        port: String,
        protocol: String,
        ipAddress: String? = null,
        packageName: String? = null
    ) {
        val metadata = mapOf(
            "port" to port,
            "protocol" to protocol,
            "ipAddress" to (ipAddress ?: "unknown"),
            "networkType" to getNetworkType(),
            "deviceModel" to android.os.Build.MODEL
        )
        
        recordInteraction(
            trapId = trapId,
            trapType = CloneDetectionService.TrapType.NETWORK,
            trapName = trapName,
            action = InteractionType.NETWORK_ACCESS,
            packageName = packageName,
            stackTrace = Thread.currentThread().stackTrace,
            metadata = metadata
        )
    }
    
    /**
     * Record process interaction with more details
     */
    fun recordProcessInteraction(
        trapId: String,
        trapName: String,
        processName: String,
        pid: Int? = null,
        packageName: String? = null
    ) {
        val metadata = mapOf(
            "processName" to processName,
            "pid" to (pid?.toString() ?: "unknown"),
            "deviceModel" to android.os.Build.MODEL,
            "androidVersion" to android.os.Build.VERSION.RELEASE
        )
        
        recordInteraction(
            trapId = trapId,
            trapType = CloneDetectionService.TrapType.PROCESS,
            trapName = trapName,
            action = InteractionType.PROCESS_ACCESS,
            packageName = packageName,
            stackTrace = Thread.currentThread().stackTrace,
            metadata = metadata
        )
    }
    
    /**
     * Get all recorded interactions for a specific trap
     */
    fun getInteractions(trapId: String): List<TrapInteraction> {
        val memoryInteractions = interactionRecords[trapId]?.toList() ?: emptyList()
        
        // For a complete history, we should also load from disk
        // But for efficiency, just return what's in memory for now
        return memoryInteractions
    }
    
    /**
     * Save interaction to encrypted file on disk
     */
    private fun saveInteractionToDisk(trapId: String, interaction: TrapInteraction) {
        try {
            val replayDir = File(context.filesDir, "replay_data")
            if (!replayDir.exists()) {
                replayDir.mkdirs()
            }
            
            val trapDir = File(replayDir, trapId)
            if (!trapDir.exists()) {
                trapDir.mkdirs()
            }
            
            // Create a filename with timestamp
            val timestamp = dateFormat.format(Date(interaction.timestamp))
            val filename = "interaction_${timestamp}_${interaction.id.substring(0, 8)}.json"
            val interactionFile = File(trapDir, filename)
            
            // Create an encrypted file with updated API
            val encryptedFile = EncryptedFile.Builder(
                interactionFile,
                context,
                masterKeyAlias,
                EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
            ).build()
            
            // Write the interaction as JSON
            encryptedFile.openFileOutput().use { outputStream ->
                val json = gson.toJson(interaction)
                outputStream.write(json.toByteArray())
                outputStream.flush()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error saving interaction to disk: ${e.message}")
            e.printStackTrace()
        }
    }
    
    /**
     * Export all interactions for a trap to a single file for analysis
     */
    suspend fun exportTrapInteractions(trapId: String): File? = withContext(Dispatchers.IO) {
        try {
            // Create export directory if it doesn't exist
            val exportDir = File(context.filesDir, "exports")
            if (!exportDir.exists()) {
                exportDir.mkdirs()
            }
            
            // Combine in-memory interactions with those saved on disk
            val allInteractions = mutableListOf<TrapInteraction>()
            
            // Add in-memory interactions
            interactionRecords[trapId]?.let { allInteractions.addAll(it) }
            
            // Add interactions from disk
            val replayDir = File(context.filesDir, "replay_data")
            val trapDir = File(replayDir, trapId)
            if (trapDir.exists()) {
                trapDir.listFiles()?.forEach { file ->
                    if (file.isFile && file.name.endsWith(".json")) {
                        try {
                            // Use the updated EncryptedFile API
                            val encryptedFile = EncryptedFile.Builder(
                                file,
                                context,
                                masterKeyAlias,
                                EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
                            ).build()
                            
                            encryptedFile.openFileInput().use { inputStream ->
                                val json = inputStream.readBytes().toString(Charsets.UTF_8)
                                val interaction = gson.fromJson(json, TrapInteraction::class.java)
                                if (!allInteractions.any { it.id == interaction.id }) {
                                    allInteractions.add(interaction)
                                }
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Error reading interaction file: ${e.message}")
                        }
                    }
                }
            }
            
            // Sort by timestamp
            allInteractions.sortBy { it.timestamp }
            
            // Create export file
            val timestamp = dateFormat.format(Date())
            val exportFile = File(exportDir, "trap_${trapId}_export_$timestamp.json")
            
            // Write to file
            FileOutputStream(exportFile).use { outputStream ->
                val replayData = ReplayData(
                    trapId = trapId,
                    exportTimestamp = System.currentTimeMillis(),
                    interactionCount = allInteractions.size,
                    firstInteractionTime = allInteractions.firstOrNull()?.timestamp ?: 0,
                    lastInteractionTime = allInteractions.lastOrNull()?.timestamp ?: 0,
                    interactions = allInteractions
                )
                
                val json = gson.toJson(replayData)
                outputStream.write(json.toByteArray())
                outputStream.flush()
            }
            
            return@withContext exportFile
        } catch (e: Exception) {
            Log.e(TAG, "Error exporting trap interactions: ${e.message}")
            e.printStackTrace()
            return@withContext null
        }
    }
    
    /**
     * Get file containing trap interactions for export
     */
    suspend fun getInteractionsFile(trapId: String): File? {
        return exportTrapInteractions(trapId)
    }
    
    /**
     * Clear recorded interactions for a specific trap
     */
    fun clearInteractions(trapId: String) {
        interactionRecords.remove(trapId)
        
        // Delete files from disk too
        val replayDir = File(context.filesDir, "replay_data")
        val trapDir = File(replayDir, trapId)
        if (trapDir.exists()) {
            trapDir.listFiles()?.forEach { it.delete() }
            trapDir.delete()
        }
    }
    
    /**
     * Get network type as string
     */
    private fun getNetworkType(): String {
        // Simplified implementation
        return try {
            val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE)
                as android.net.ConnectivityManager
            
            val activeNetwork = connectivityManager.activeNetwork
            if (activeNetwork != null) {
                val networkCapabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
                when {
                    networkCapabilities?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) == true -> "WIFI"
                    networkCapabilities?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "CELLULAR"
                    else -> "OTHER"
                }
            } else {
                "NONE"
            }
        } catch (e: Exception) {
            "UNKNOWN"
        }
    }
    
    /**
     * Enum for types of trap interactions
     */
    enum class InteractionType {
        FILE_ACCESS,
        NETWORK_ACCESS,
        PROCESS_ACCESS,
        CUSTOM_ACCESS
    }
    
    /**
     * Data class for trap interaction details
     */
    data class TrapInteraction(
        val id: String,
        val trapId: String,
        val trapType: String,
        val trapName: String,
        val timestamp: Long,
        val interactionType: InteractionType,
        val packageName: String,
        val stackTrace: String? = null,
        val metadata: Map<String, Any> = emptyMap()
    )
    
    /**
     * Data class for export format
     */
    data class ReplayData(
        val trapId: String,
        val exportTimestamp: Long,
        val interactionCount: Int,
        val firstInteractionTime: Long,
        val lastInteractionTime: Long,
        val interactions: List<TrapInteraction>
    )
} 