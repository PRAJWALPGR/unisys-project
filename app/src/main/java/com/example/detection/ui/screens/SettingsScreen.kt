package com.example.detection.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.detection.ui.components.*
import com.example.detection.ui.viewmodels.SettingsViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel = viewModel()
) {
    val scrollState = rememberScrollState()
    
    // Clone Detection settings
    val isCloneDetectionEnabled by viewModel.isCloneDetectionEnabled.collectAsState()
    val scanFrequency by viewModel.scanFrequency.collectAsState()
    
    // Network Security settings
    val isNetworkMonitoringEnabled by viewModel.isNetworkMonitoringEnabled.collectAsState()
    val isMirrorReflectionEnabled by viewModel.isMirrorReflectionEnabled.collectAsState()
    val isPolymorphicResponseEnabled by viewModel.isPolymorphicResponseEnabled.collectAsState()
    
    // Neural Fingerprint settings
    val isNeuralFingerprintEnabled by viewModel.isNeuralFingerprintEnabled.collectAsState()
    val isAdaptiveLearningEnabled by viewModel.isAdaptiveLearningEnabled.collectAsState()
    
    // Honeypot Traps settings
    val isHoneypotSystemEnabled by viewModel.isHoneypotSystemEnabled.collectAsState()
    val isEmotionalDeceptionEnabled by viewModel.isEmotionalDeceptionEnabled.collectAsState()
    val isPolymorphicHoneypotsEnabled by viewModel.isPolymorphicHoneypotsEnabled.collectAsState()
    val isFakeCryptoWalletsEnabled by viewModel.isFakeCryptoWalletsEnabled.collectAsState()
    val isInvisibleOverlayTrapsEnabled by viewModel.isInvisibleOverlayTrapsEnabled.collectAsState()
    val isSelfHealingHoneypotsEnabled by viewModel.isSelfHealingHoneypotsEnabled.collectAsState()
    
    // Deep Scan settings
    val isDeepScanEnabled by viewModel.isDeepScanEnabled.collectAsState()
    val isRootDetectionEnabled by viewModel.isRootDetectionEnabled.collectAsState()
    val isPackageIntegrityEnabled by viewModel.isPackageIntegrityEnabled.collectAsState()
    
    // Blockchain Verification settings
    val isBlockchainVerificationEnabled by viewModel.isBlockchainVerificationEnabled.collectAsState()
    val blockchainSyncFrequency by viewModel.blockchainSyncFrequency.collectAsState()
    
    // Advanced Controls settings
    val isAutoHealingEnabled by viewModel.isAutoHealingEnabled.collectAsState()
    val isArThreatVisualizationEnabled by viewModel.isArThreatVisualizationEnabled.collectAsState()
    val isStealthModeEnabled by viewModel.isStealthModeEnabled.collectAsState()
    val isPredictiveThreatWarningsEnabled by viewModel.isPredictiveThreatWarningsEnabled.collectAsState()
    
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
                .verticalScroll(scrollState)
        ) {
            Text(
                text = "Settings",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(bottom = 16.dp)
            )
            
            // Clone Detection Section
            SettingsCategory(
                title = "Clone Detection",
                icon = Icons.Default.Security
            ) {
                SettingsToggle(
                    title = "Clone Detection",
                    description = "Enable or disable clone detection scanning",
                    isChecked = isCloneDetectionEnabled,
                    onCheckedChange = { viewModel.toggleCloneDetection(it) }
                )
                
                SettingsDropdown(
                    title = "Scan Frequency",
                    description = "Set how frequently clone detection scans are performed",
                    options = listOf("Low", "Medium", "High"),
                    selectedOption = scanFrequency,
                    onOptionSelected = { viewModel.setScanFrequency(it) }
                )
            }
            
            // Network Security Section
            SettingsCategory(
                title = "Network Security",
                icon = Icons.Default.NetworkCheck
            ) {
                SettingsToggle(
                    title = "Network Monitoring",
                    description = "Enable monitoring of network traffic for suspicious activities",
                    isChecked = isNetworkMonitoringEnabled,
                    onCheckedChange = { viewModel.toggleNetworkMonitoring(it) }
                )
                
                SettingsToggle(
                    title = "Mirror Reflection Test",
                    description = "Enable network reflection testing to detect network spoofing",
                    isChecked = isMirrorReflectionEnabled,
                    onCheckedChange = { viewModel.toggleMirrorReflection(it) }
                )
                
                SettingsToggle(
                    title = "Polymorphic Response Handling",
                    description = "Enable dynamic response to network threats",
                    isChecked = isPolymorphicResponseEnabled,
                    onCheckedChange = { viewModel.togglePolymorphicResponse(it) }
                )
            }
            
            // Neural Fingerprint Section
            SettingsCategory(
                title = "Neural Fingerprint",
                icon = Icons.Default.Fingerprint
            ) {
                SettingsToggle(
                    title = "Neural Fingerprint Scanning",
                    description = "Enable behavioral pattern analysis for threat detection",
                    isChecked = isNeuralFingerprintEnabled,
                    onCheckedChange = { viewModel.toggleNeuralFingerprint(it) }
                )
                
                SettingsToggle(
                    title = "Adaptive Learning Mode",
                    description = "Enable adaptive learning for improved threat detection",
                    isChecked = isAdaptiveLearningEnabled,
                    onCheckedChange = { viewModel.toggleAdaptiveLearning(it) }
                )
            }
            
            // Honeypot Traps Section
            SettingsCategory(
                title = "Honeypot Traps",
                icon = Icons.Default.BugReport
            ) {
                SettingsToggle(
                    title = "Honeypot System",
                    description = "Enable honeypot traps to detect and analyze malicious activities",
                    isChecked = isHoneypotSystemEnabled,
                    onCheckedChange = { viewModel.toggleHoneypotSystem(it) }
                )
                
                SettingsToggle(
                    title = "Emotional Deception Environment (EDE)",
                    description = "Enable psychological manipulation techniques for traps",
                    isChecked = isEmotionalDeceptionEnabled,
                    onCheckedChange = { viewModel.toggleEmotionalDeception(it) }
                )
                
                SettingsToggle(
                    title = "Polymorphic Honeypots",
                    description = "Enable self-adapting honeypot behaviors",
                    isChecked = isPolymorphicHoneypotsEnabled,
                    onCheckedChange = { viewModel.togglePolymorphicHoneypots(it) }
                )
                
                SettingsToggle(
                    title = "Fake Crypto Wallets",
                    description = "Enable fake cryptocurrency wallet traps",
                    isChecked = isFakeCryptoWalletsEnabled,
                    onCheckedChange = { viewModel.toggleFakeCryptoWallets(it) }
                )
                
                SettingsToggle(
                    title = "Invisible Overlay Traps",
                    description = "Enable invisible UI overlay traps to detect screen scrapers",
                    isChecked = isInvisibleOverlayTrapsEnabled,
                    onCheckedChange = { viewModel.toggleInvisibleOverlayTraps(it) }
                )
                
                SettingsToggle(
                    title = "Self-Healing Honeypots",
                    description = "Enable auto-recovery for compromised honeypots",
                    isChecked = isSelfHealingHoneypotsEnabled,
                    onCheckedChange = { viewModel.toggleSelfHealingHoneypots(it) }
                )
            }
            
            // Deep Scan Section
            SettingsCategory(
                title = "Deep Scan",
                icon = Icons.Default.Search
            ) {
                SettingsToggle(
                    title = "Deep Scan Engine",
                    description = "Enable comprehensive system scanning",
                    isChecked = isDeepScanEnabled,
                    onCheckedChange = { viewModel.toggleDeepScan(it) }
                )
                
                SettingsToggle(
                    title = "Root Detection",
                    description = "Enable detection of rooted or jailbroken devices",
                    isChecked = isRootDetectionEnabled,
                    onCheckedChange = { viewModel.toggleRootDetection(it) }
                )
                
                SettingsToggle(
                    title = "Package Integrity Verification",
                    description = "Enable verification of app package integrity",
                    isChecked = isPackageIntegrityEnabled,
                    onCheckedChange = { viewModel.togglePackageIntegrity(it) }
                )
            }
            
            // Blockchain Verification Section
            SettingsCategory(
                title = "Blockchain Verification",
                icon = Icons.Default.Link
            ) {
                SettingsToggle(
                    title = "Blockchain Verification",
                    description = "Enable blockchain-based verification mechanisms",
                    isChecked = isBlockchainVerificationEnabled,
                    onCheckedChange = { viewModel.toggleBlockchainVerification(it) }
                )
                
                SettingsDropdown(
                    title = "Sync Frequency",
                    description = "Set how frequently blockchain verification occurs",
                    options = listOf("Manual", "Hourly", "Daily"),
                    selectedOption = blockchainSyncFrequency,
                    onOptionSelected = { viewModel.setBlockchainSyncFrequency(it) }
                )
            }
            
            // Advanced Controls Section
            SettingsCategory(
                title = "Advanced Controls",
                icon = Icons.Default.Settings
            ) {
                SettingsToggle(
                    title = "Auto-Healing Mechanism",
                    description = "Enable self-repair capabilities for the security system",
                    isChecked = isAutoHealingEnabled,
                    onCheckedChange = { viewModel.toggleAutoHealing(it) }
                )
                
                SettingsToggle(
                    title = "AR Threat Visualization",
                    description = "Enable augmented reality visualization of security threats",
                    isChecked = isArThreatVisualizationEnabled,
                    onCheckedChange = { viewModel.toggleArThreatVisualization(it) }
                )
                
                SettingsToggle(
                    title = "Stealth Mode",
                    description = "Enable stealth operation to hide security activities from threats",
                    isChecked = isStealthModeEnabled,
                    onCheckedChange = { viewModel.toggleStealthMode(it) }
                )
                
                SettingsToggle(
                    title = "Predictive Threat Warnings",
                    description = "Enable AI-based prediction of potential security threats",
                    isChecked = isPredictiveThreatWarningsEnabled,
                    onCheckedChange = { viewModel.togglePredictiveThreatWarnings(it) }
                )
            }
            
            Spacer(modifier = Modifier.height(32.dp))
        }
    }
} 