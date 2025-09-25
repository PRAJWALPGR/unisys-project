package com.example.detection.service

import android.content.Context
import java.util.concurrent.ConcurrentHashMap
import kotlin.random.Random

/**
 * Dynamic Trap Generation System
 * Automatically generates new honeypot traps based on observed patterns and high-activity traps
 */
class DynamicTrapGenerator(
    private val context: Context,
    private val cloneDetectionService: CloneDetectionService
) {
    // Track frequency of trap access to determine where to spawn new traps
    private val trapAccessFrequency = ConcurrentHashMap<String, Int>()
    
    // Recently generated trap IDs
    private val recentlyGeneratedTraps = mutableListOf<String>()
    
    // Maximum number of dynamically generated traps allowed
    private val MAX_DYNAMIC_TRAPS = 15
    
    // Threshold to trigger new trap generation
    private val GENERATION_THRESHOLD = 5
    
    // Track parent-child relationships for trap chains
    private val trapChains = ConcurrentHashMap<String, MutableList<String>>()
    
    // Templates for trap generation
    private val networkTrapTemplates = listOf(
        TrapTemplate("Dynamic Network Trap", CloneDetectionService.TrapType.NETWORK, 
            { parent -> generatePortNearby(parent) }, 
            CloneDetectionService.AlertLevel.MEDIUM, 
            "Dynamically generated network trap based on suspicious activity"
        ),
        TrapTemplate("Sensitive API Monitor", CloneDetectionService.TrapType.NETWORK, 
            { _ -> "443" }, 
            CloneDetectionService.AlertLevel.HIGH, 
            "Monitors attempts to access sensitive API endpoints"
        )
    )
    
    private val fileTrapTemplates = listOf(
        TrapTemplate("Dynamic File Trap", CloneDetectionService.TrapType.FILE, 
            { parent -> generateFilepathVariant(parent) }, 
            CloneDetectionService.AlertLevel.MEDIUM, 
            "Dynamically generated file trap based on suspicious activity"
        ),
        TrapTemplate("Decoy Config File", CloneDetectionService.TrapType.FILE, 
            { _ -> "config/sensitive_data.json" }, 
            CloneDetectionService.AlertLevel.HIGH, 
            "Monitors attempts to access fake configuration files"
        )
    )
    
    private val processTrapTemplates = listOf(
        TrapTemplate("Dynamic Process Monitor", CloneDetectionService.TrapType.PROCESS, 
            { parent -> generateProcessVariant(parent) }, 
            CloneDetectionService.AlertLevel.MEDIUM, 
            "Dynamically generated process monitor based on suspicious activity"
        ),
        TrapTemplate("System Service Decoy", CloneDetectionService.TrapType.PROCESS, 
            { _ -> "system_service" }, 
            CloneDetectionService.AlertLevel.HIGH, 
            "Monitors attempts to access fake system services"
        )
    )
    
    /**
     * Record an access to a trap and potentially generate new traps
     */
    fun recordTrapAccess(trapId: String) {
        // Increment access counter for this trap
        val currentCount = trapAccessFrequency.getOrPut(trapId) { 0 }
        trapAccessFrequency[trapId] = currentCount + 1
        
        // Check if we should generate a new trap
        if (currentCount + 1 >= GENERATION_THRESHOLD) {
            // Only generate if we're below the max limit
            val activeTraps = cloneDetectionService.getActiveTraps()
            if (activeTraps.size < MAX_DYNAMIC_TRAPS) {
                generateRelatedTrap(trapId)
                // Reset counter after generating a trap
                trapAccessFrequency[trapId] = 0
            }
        }
    }
    
    /**
     * Generate a new trap related to an existing frequently-accessed trap
     */
    private fun generateRelatedTrap(parentTrapId: String): String? {
        val parentTrap = cloneDetectionService.getActiveTraps().find { it.id == parentTrapId } ?: return null
        
        // Select a template based on the parent trap type
        val template = when (parentTrap.type) {
            CloneDetectionService.TrapType.NETWORK -> networkTrapTemplates.random()
            CloneDetectionService.TrapType.FILE -> fileTrapTemplates.random()
            CloneDetectionService.TrapType.PROCESS -> processTrapTemplates.random()
        }
        
        // Generate the target based on parent trap's target
        val target = template.targetGenerator(parentTrap.target)
        
        // Avoid duplicates - check if a trap with this target already exists
        if (cloneDetectionService.getActiveTraps().any { it.type == template.type && it.target == target }) {
            return null
        }
        
        // Create the new trap
        val newTrapId = cloneDetectionService.addTrap(
            name = "${template.namePrefix} ${Random.nextInt(1000)}",
            type = template.type,
            target = target,
            alertLevel = template.alertLevel,
            description = template.description
        )
        
        // Record the parent-child relationship
        trapChains.getOrPut(parentTrapId) { mutableListOf() }.add(newTrapId)
        
        // Add to recently generated list
        recentlyGeneratedTraps.add(newTrapId)
        if (recentlyGeneratedTraps.size > 10) {
            recentlyGeneratedTraps.removeAt(0)
        }
        
        return newTrapId
    }
    
    /**
     * Generate a network port number close to the parent trap
     */
    private fun generatePortNearby(parentTarget: String): String {
        val parentPort = parentTarget.toIntOrNull() ?: return (8000 + Random.nextInt(1000)).toString()
        val offset = Random.nextInt(-10, 11)
        val newPort = parentPort + offset
        return if (newPort in 1..65535) newPort.toString() else parentPort.toString()
    }
    
    /**
     * Generate a file path variant based on the parent trap
     */
    private fun generateFilepathVariant(parentTarget: String): String {
        // If parent target is a directory, create a file within it
        if (parentTarget.endsWith("/")) {
            return parentTarget + "sensitive_" + Random.nextInt(1000) + ".dat"
        }
        
        // If parent target is a file, create a similar file
        val lastSlash = parentTarget.lastIndexOf('/')
        if (lastSlash != -1) {
            val directory = parentTarget.substring(0, lastSlash + 1)
            val filename = parentTarget.substring(lastSlash + 1)
            
            // Generate a variant of the filename
            val parts = filename.split(".")
            val name = parts[0]
            val extension = if (parts.size > 1) "." + parts[1] else ""
            
            val variants = listOf("_backup", "_config", "_key", "_secret", "_temp")
            return directory + name + variants.random() + extension
        }
        
        return "secure/decoy_" + Random.nextInt(1000) + ".dat"
    }
    
    /**
     * Generate a process name variant based on the parent trap
     */
    private fun generateProcessVariant(parentTarget: String): String {
        val processSuffixes = listOf("_helper", "_daemon", "_service", "_agent", "_manager")
        return parentTarget + processSuffixes.random()
    }
    
    /**
     * Create a set of default trap templates that the user can apply
     */
    fun getAvailableTemplates(): List<TrapTemplateGroup> {
        return listOf(
            TrapTemplateGroup(
                name = "Network Protection Suite",
                description = "A set of traps to monitor network activity",
                traps = listOf(
                    TrapDefinition("API Gateway Monitor", CloneDetectionService.TrapType.NETWORK, 
                        "8080", CloneDetectionService.AlertLevel.MEDIUM, 
                        "Monitors attempts to access the API gateway"),
                    TrapDefinition("Secure Socket Monitor", CloneDetectionService.TrapType.NETWORK, 
                        "443", CloneDetectionService.AlertLevel.HIGH, 
                        "Detects HTTPS interception attempts"),
                    TrapDefinition("Database Port Monitor", CloneDetectionService.TrapType.NETWORK, 
                        "5432", CloneDetectionService.AlertLevel.HIGH, 
                        "Monitors attempts to access the database port")
                )
            ),
            TrapTemplateGroup(
                name = "File System Guards",
                description = "Traps to protect sensitive files and directories",
                traps = listOf(
                    TrapDefinition("Credentials Monitor", CloneDetectionService.TrapType.FILE, 
                        "secure/credentials.dat", CloneDetectionService.AlertLevel.HIGH, 
                        "Monitors attempts to access fake credentials"),
                    TrapDefinition("Config Directory Guard", CloneDetectionService.TrapType.FILE, 
                        "config/", CloneDetectionService.AlertLevel.MEDIUM, 
                        "Protects the configuration directory"),
                    TrapDefinition("Keystore Monitor", CloneDetectionService.TrapType.FILE, 
                        "keys/app.keystore", CloneDetectionService.AlertLevel.HIGH, 
                        "Monitors attempts to access the app keystore")
                )
            ),
            TrapTemplateGroup(
                name = "Process Sentinels",
                description = "Monitors attempts to access or manipulate system processes",
                traps = listOf(
                    TrapDefinition("System Service Guard", CloneDetectionService.TrapType.PROCESS, 
                        "system_server", CloneDetectionService.AlertLevel.HIGH, 
                        "Monitors attempts to access the system server"),
                    TrapDefinition("Background Service Monitor", CloneDetectionService.TrapType.PROCESS, 
                        "background_service", CloneDetectionService.AlertLevel.MEDIUM, 
                        "Detects monitoring of background services"),
                    TrapDefinition("Package Manager Guard", CloneDetectionService.TrapType.PROCESS, 
                        "package_manager", CloneDetectionService.AlertLevel.HIGH, 
                        "Protects against package manager interception")
                )
            )
        )
    }
    
    /**
     * Apply a template group to create multiple traps at once
     */
    fun applyTemplateGroup(groupName: String): List<String> {
        val group = getAvailableTemplates().find { it.name == groupName }
        if (group == null) return emptyList()
        
        val createdTrapIds = mutableListOf<String>()
        
        for (trapDef in group.traps) {
            val id = cloneDetectionService.addTrap(
                name = trapDef.name,
                type = trapDef.type,
                target = trapDef.target,
                alertLevel = trapDef.alertLevel,
                description = trapDef.description
            )
            createdTrapIds.add(id)
        }
        
        return createdTrapIds
    }
    
    /**
     * Get recently generated traps
     */
    fun getRecentlyGeneratedTraps(): List<String> {
        return recentlyGeneratedTraps.toList()
    }
    
    /**
     * Get child traps generated from a parent trap
     */
    fun getChildTraps(parentTrapId: String): List<String> {
        return trapChains[parentTrapId]?.toList() ?: emptyList()
    }
    
    /**
     * Clear all dynamically generated traps
     */
    fun clearDynamicTraps() {
        val dynamicIds = recentlyGeneratedTraps.toList()
        
        for (id in dynamicIds) {
            cloneDetectionService.removeTrap(id)
        }
        
        recentlyGeneratedTraps.clear()
        trapChains.clear()
    }
    
    /**
     * Data class for trap template with target generator function
     */
    data class TrapTemplate(
        val namePrefix: String,
        val type: CloneDetectionService.TrapType,
        val targetGenerator: (String) -> String,
        val alertLevel: CloneDetectionService.AlertLevel,
        val description: String
    )
    
    /**
     * Data class for a trap definition within a template group
     */
    data class TrapDefinition(
        val name: String,
        val type: CloneDetectionService.TrapType,
        val target: String,
        val alertLevel: CloneDetectionService.AlertLevel,
        val description: String
    )
    
    /**
     * Data class for a group of related trap templates
     */
    data class TrapTemplateGroup(
        val name: String,
        val description: String,
        val traps: List<TrapDefinition>
    )
} 