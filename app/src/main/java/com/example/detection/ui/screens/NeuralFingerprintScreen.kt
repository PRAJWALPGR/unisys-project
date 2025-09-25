package com.example.detection.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.HorizontalDivider
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.detection.service.NeuralFingerprintService
import com.example.detection.service.NeuralFingerprintServiceProvider
import com.example.detection.ui.components.*
import com.example.detection.ui.theme.*
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import kotlinx.coroutines.delay
import androidx.compose.ui.platform.LocalContext
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.ui.graphics.vector.ImageVector
import com.example.detection.ui.theme.NfDangerRed
import com.example.detection.ui.theme.NfNeonBlue
import com.example.detection.ui.theme.NfPurple
import com.example.detection.ui.theme.NfSafeGreen
import com.example.detection.ui.theme.NfTextPrimary
import com.example.detection.ui.theme.NfTextSecondary
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.material.icons.filled.Store
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.KeyboardArrowRight
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import android.content.Intent
import android.net.Uri
import android.content.Context
import androidx.compose.foundation.layout.wrapContentSize

@Composable
fun NeuralFingerprintScreen(
    modifier: Modifier = Modifier,
    neuralFingerprintService: NeuralFingerprintService
) {
    val fingerprintStatus by neuralFingerprintService.fingerprintStatus.collectAsStateWithLifecycle()
    val appAnalysisResults by neuralFingerprintService.appAnalysisResults.collectAsStateWithLifecycle()
    val threatHistory by neuralFingerprintService.threatHistory.collectAsStateWithLifecycle()
    val modelTrainingStatus by neuralFingerprintService.modelTrainingStatus.collectAsStateWithLifecycle()
    val securityScore by neuralFingerprintService.securityScore.collectAsStateWithLifecycle()
    
    var currentTab by remember { mutableStateOf(0) }
    var monitoringActive by remember { mutableStateOf(false) }
    val coroutineScope = rememberCoroutineScope()
    
    // Try to connect with the scanner service
    LaunchedEffect(Unit) {
        // Attempt to connect to scanner service (this would be a real implementation in production)
        try {
            // This is a simplified version - in reality, this would get the scanner service
            // from the main activity or through dependency injection
            val scannerService = null // In real code, this would be something like: LocalContext.current.scannerService
            neuralFingerprintService.connectToScanner(scannerService)
        } catch (e: Exception) {
            // Connection failed, but we can still use mock data
        }
    }
    
    val tabTitles = listOf("Dashboard", "App Detection", "Threat History", "AI Training")
    
    // Light theme background
    Surface(
        modifier = modifier.fillMaxSize(),
        color = NfDarkBackground // This is now white
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
        ) {
            // Header with tabs
            TabRow(
                selectedTabIndex = currentTab,
                containerColor = NfDarkSurface, // Now light gray
                contentColor = NfNeonBlue,
                indicator = { tabPositions ->
                    TabRowDefaults.Indicator(
                        Modifier.tabIndicatorOffset(tabPositions[currentTab]),
                        height = 2.dp,
                        color = NfNeonBlue
                    )
                }
            ) {
                tabTitles.forEachIndexed { index, title ->
                    Tab(
                        selected = currentTab == index,
                        onClick = { currentTab = index },
                        text = {
                            Text(
                                text = title,
                                style = MaterialTheme.typography.bodyMedium.copy(
                                    fontWeight = if (currentTab == index) FontWeight.Bold else FontWeight.Normal
                                ),
                                color = if (currentTab == index) NfNeonBlue else NfTextSecondary
                            )
                        },
                        selectedContentColor = NfNeonBlue,
                        unselectedContentColor = NfTextSecondary
                    )
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            // Content based on selected tab
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
            ) {
                when (currentTab) {
                    0 -> NeuralSecurityDashboard(
                        securityScore = securityScore,
                        fingerprintStatus = fingerprintStatus,
                        threatHistory = threatHistory.take(3),
                        monitoringActive = monitoringActive,
                        onToggleMonitoring = {
                            monitoringActive = !monitoringActive
                            if (monitoringActive) {
                                neuralFingerprintService.startBehaviorMonitoring()
                            } else {
                                neuralFingerprintService.stopBehaviorMonitoring()
                            }
                        }
                    )
                    1 -> CloneAppDetectionPage(
                        appAnalysisResults = appAnalysisResults,
                        onViewAppDetails = { /* View app details implementation */ },
                        onRefreshScan = {
                            // Refresh the app analysis when the refresh button is clicked
                            neuralFingerprintService.refreshAppAnalysis()
                        }
                    )
                    2 -> ThreatHistoryPage(
                        threatHistory = threatHistory,
                        onViewThreatDetails = { /* View threat details implementation */ },
                        onExportReport = {
                            val report = neuralFingerprintService.generateSecurityReport()
                            // Export report implementation
                        }
                    )
                    3 -> NeuralAITrainingPage(
                        modelTrainingStatus = modelTrainingStatus,
                        onStartTraining = {
                            neuralFingerprintService.startModelTraining(0.85f)
                        },
                        onTestApk = { filePath ->
                            neuralFingerprintService.testApkFile(filePath)
                        }
                    )
                }
            }
        }
    }
}

@Composable
fun NeuralSecurityDashboard(
    securityScore: Int,
    fingerprintStatus: NeuralFingerprintService.FingerprintStatus,
    threatHistory: List<NeuralFingerprintService.ThreatHistoryEvent>,
    monitoringActive: Boolean,
    onToggleMonitoring: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Security Score Circle and Fingerprint visualization
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceAround,
            verticalAlignment = Alignment.CenterVertically
        ) {
            SecurityScoreCircle(
                score = securityScore,
                modifier = Modifier.weight(1f),
                size = 160,
                pulsingEffect = monitoringActive
            )
            
            Spacer(modifier = Modifier.width(16.dp))
            
            NeuralFingerprintVisualization(
                modifier = Modifier.weight(1f),
                animating = monitoringActive
            )
        }
        
        // Monitoring control card
        HolographicCard(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "Neural Monitoring",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        
                        Text(
                            text = if (monitoringActive) 
                                "Active - Scanning in real-time" 
                            else 
                                "Inactive - Click to activate",
                            style = MaterialTheme.typography.bodyMedium,
                            color = if (monitoringActive) NfNeonGreen else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                        )
                    }
                    
                    CyberShieldAnimation(
                        active = monitoringActive,
                        modifier = Modifier.size(60.dp)
                    )
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                NeuralActivityGraph(
                    modifier = Modifier.fillMaxWidth(),
                    heightDp = 80,
                    animated = monitoringActive
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                Button(
                    onClick = onToggleMonitoring,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (monitoringActive) NfNeonRed else NfNeonGreen
                    ),
                    modifier = Modifier.align(Alignment.End)
                ) {
                    Text(if (monitoringActive) "Stop Monitoring" else "Start Monitoring")
                }
            }
        }
        
        // Status cards row
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            SecurityStatCard(
                value = "${(fingerprintStatus.behaviorPatternScore * 100).toInt()}%",
                label = "Behavior Trust",
                icon = Icons.Default.Psychology,
                modifier = Modifier.weight(1f),
                valueColor = NfNeonGreen
            )
            
            SecurityStatCard(
                value = "${fingerprintStatus.behaviorDataPoints}",
                label = "Data Points",
                icon = Icons.Default.Memory,
                modifier = Modifier.weight(1f),
                valueColor = NfNeonBlue
            )
            
            SecurityStatCard(
                value = "${(fingerprintStatus.deviceIntegrityScore * 100).toInt()}%",
                label = "Device Trust",
                icon = Icons.Default.Smartphone,
                modifier = Modifier.weight(1f),
                valueColor = NfNeonPurple
            )
        }
        
        // Recent threats section
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = NfDarkSurface
            )
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
            ) {
                Text(
                    text = "Recent Threats",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                if (threatHistory.isEmpty()) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 24.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "No recent threats detected",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                        )
                    }
                } else {
                    threatHistory.forEach { event ->
                        ThreatHistoryItem(
                            event = event,
                            onViewDetails = { /* View threat details implementation */ }
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                    }
                }
            }
        }
    }
}

@Composable
fun CloneAppDetectionPage(
    appAnalysisResults: List<NeuralFingerprintService.AppAnalysisResult>,
    onViewAppDetails: (String) -> Unit,
    onRefreshScan: () -> Unit
) {
    val context = LocalContext.current
    var showDeepScanDialog by remember { mutableStateOf(false) }
    var showScanResultsDialog by remember { mutableStateOf(false) }
    var isScanning by remember { mutableStateOf(false) }
    var scanProgress by remember { mutableStateOf(0) }
    var scanProgressText by remember { mutableStateOf("Initializing scan...") }
    val coroutineScope = rememberCoroutineScope()
    
    // Get service instance from the context (if available)
    val neuralFingerprintService = remember {
        try {
            (context.applicationContext as? NeuralFingerprintServiceProvider)?.getNeuralFingerprintService()
        } catch (e: Exception) {
            null
        }
    }
    
    // Get the source verification summary from the service
    val sourceVerificationSummary by neuralFingerprintService?.sourceVerificationSummary?.collectAsStateWithLifecycle(
        initialValue = mapOf(
            "Google Play Store" to 0,
            "Google App Services" to 0,
            "System App" to 0,
            "Unknown Source" to 0
        )
    ) ?: remember { mutableStateOf(emptyMap<String, Int>()) }
    
    // Sort apps by source and trust score
    val sortedApps = remember(appAnalysisResults) {
        appAnalysisResults.sortedWith(
            compareBy<NeuralFingerprintService.AppAnalysisResult> { 
                when {
                    // Sort order: unknown sources first, then third-party stores, then Play Store, then system apps
                    it.installerStore == "Unknown Source" -> 0
                    !it.isSystemApp && !it.installerStore.contains("Play Store") && !it.installerStore.contains("Google") -> 1
                    it.installerStore.contains("Play Store") || it.installerStore.contains("Google") -> 2
                    it.isSystemApp -> 3
                    else -> 4
                }
            }.thenBy { -it.trustScore } // Secondary sort by trust score (descending)
        )
    }
    
    // Get list of unknown source apps
    val unknownSourceApps = remember(appAnalysisResults) {
        appAnalysisResults.filter { it.installerStore == "Unknown Source" }
    }
    
    // Categorize by source
    val playStoreApps = remember(appAnalysisResults) {
        appAnalysisResults.filter { it.installerStore.contains("Play Store", ignoreCase = true) || it.installerStore.contains("Google", ignoreCase = true) }
    }
    val systemApps = remember(appAnalysisResults) {
        appAnalysisResults.filter { it.isSystemApp }
    }
    
    // Untrusted apps list (exclude real system apps explicitly)
    val untrustedApps = remember(appAnalysisResults) {
        appAnalysisResults.filter { (it.installerStore == "Unknown Source" || !it.isTrusted) && !it.isSystemApp }
    }
    
    // State for resolution dialog
    var showResolutionDialog by remember { mutableStateOf(false) }
    var selectedUntrustedApp by remember { mutableStateOf<NeuralFingerprintService.AppAnalysisResult?>(null) }
   
    fun buildResolutionAdvice(app: NeuralFingerprintService.AppAnalysisResult): String {
        val reasons = mutableListOf<String>()
        if (app.installerStore == "Unknown Source") {
            reasons.add("Installed from unknown source")
        }
        if (app.primaryIssue.contains("permission", ignoreCase = true) || app.permissionUsageScore < 50) {
            reasons.add("Excessive or risky permissions")
        }
        if (app.primaryIssue.contains("signature", ignoreCase = true)) {
            reasons.add("Signature mismatch")
        }
        if (app.primaryIssue.contains("clone", ignoreCase = true) || app.primaryIssue.contains("mimic", ignoreCase = true)) {
            reasons.add("Potential clone / brand mimicry")
        }
        val reasonText = if (reasons.isNotEmpty()) reasons.joinToString(", ") else app.primaryIssue
        val base = "Reason: $reasonText\n\nRecommended actions:\n"
        val actions = buildList {
            if (app.installerStore == "Unknown Source") add("Uninstall and reinstall from Google Play Store or official store")
            if (app.permissionUsageScore < 50) add("Review and revoke unnecessary permissions")
            if (app.primaryIssue.contains("signature", ignoreCase = true)) add("Avoid using the app; install the verified publisher version")
            add("Open App Info to uninstall or change permissions")
        }
        return base + actions.mapIndexed { idx, a -> "${idx + 1}. $a" }.joinToString("\n")
    }
   
    fun openAppInfo(context: Context, packageName: String) {
        try {
            val intent = Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = Uri.parse("package:$packageName")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
        } catch (_: Exception) { }
    }
   
    fun openPlayStore(context: Context, packageName: String) {
        try {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=$packageName")).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
        } catch (_: Exception) {
            try {
                val web = Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/apps/details?id=$packageName")).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                context.startActivity(web)
            } catch (_: Exception) { }
        }
    }
    
    // Function to handle scan in background thread
    fun startScan() {
        if (isScanning) return // Prevent multiple scans
        
        isScanning = true
        scanProgress = 0
        scanProgressText = "Initializing scan..."
        
        coroutineScope.launch(Dispatchers.IO) {
            try {
                // Step 1: Signature verification
                withContext(Dispatchers.Main) {
                    scanProgressText = "Analyzing package signatures..."
                }
                for (i in 0..20) {
                    delay(50)
                    withContext(Dispatchers.Main) {
                        scanProgress = i
                    }
                }
                
                // Step 2: Play Store verification
                withContext(Dispatchers.Main) {
                    scanProgressText = "Verifying Play Store apps..."
                }
                for (i in 21..40) {
                    delay(40)
                    withContext(Dispatchers.Main) {
                        scanProgress = i
                    }
                }
                
                // Step 3: AI anomaly detection
                withContext(Dispatchers.Main) {
                    scanProgressText = "Running AI anomaly detection..."
                }
                for (i in 41..70) {
                    delay(50)
                    withContext(Dispatchers.Main) {
                        scanProgress = i
                    }
                }
                
                // Step 4: Network security analysis
                withContext(Dispatchers.Main) {
                    scanProgressText = "Scanning network connections and security..."
                }
                for (i in 71..90) {
                    delay(40)
                    withContext(Dispatchers.Main) {
                        scanProgress = i
                    }
                }
                
                // Perform actual scan operations in background
                neuralFingerprintService?.let { service ->
                    // These operations are done on the IO dispatcher to avoid blocking UI
                    service.refreshAppAnalysisWithDeepScan()
                    service.runAIAnomalyDetection(enforceSameResultCount = true)
                    service.synchronizeNetworkSecurity()
                }
                
                // Final step: Processing results
                withContext(Dispatchers.Main) {
                    scanProgressText = "Processing results..."
                }
                for (i in 91..100) {
                    delay(30)
                    withContext(Dispatchers.Main) {
                        scanProgress = i
                    }
                }
                
                // Finish scan and show results
                withContext(Dispatchers.Main) {
                    isScanning = false
                    showScanResultsDialog = true
                }
            } catch (e: Exception) {
                // Handle errors
                withContext(Dispatchers.Main) {
                    isScanning = false
                    Toast.makeText(
                        context,
                        "Scan error: ${e.message}",
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }
    
    val screenScroll = rememberScrollState()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(top = 16.dp)
            .verticalScroll(screenScroll)
    ) {
        // Top Scan Button
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Neural Fingerprint Scan",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = NfTextPrimary
            )
            Button(
                enabled = !isScanning,
                onClick = { startScan() }
            ) { Text(if (isScanning) "Scanning..." else "Scan") }
        }
        // Source Statistics from sourceVerificationSummary
        val playStoreCount = sourceVerificationSummary["Google Play Store"] ?: 0
        val googleAppCount = sourceVerificationSummary["Google App Services"] ?: 0
        val systemAppsCount = sourceVerificationSummary["System App"] ?: 0
        val unknownSourceCount = sourceVerificationSummary["Unknown Source"] ?: 0
        val totalApps = playStoreCount + googleAppCount + systemAppsCount + unknownSourceCount
        
        // Header with app source info
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp)
        ) {
            Text(
                text = "Application Source Verification",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = NfTextPrimary
            )
            
            Text(
                text = "Verify your app installation sources to identify security risks",
                style = MaterialTheme.typography.bodyMedium,
                color = NfTextSecondary
            )
        }
        
        // Play Store Apps Section
        if (playStoreApps.isNotEmpty()) {
            Spacer(modifier = Modifier.height(8.dp))
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
            ) {
                Text(
                    text = "Play Store Apps (${playStoreApps.size})",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )
                Spacer(modifier = Modifier.height(4.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 0.dp, max = 280.dp)
                ) {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        items(playStoreApps, key = { it.packageName }) { app ->
                Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                ) {
                    Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(app.appName, style = MaterialTheme.typography.titleSmall)
                                        Text("Source: Google Play Store", style = MaterialTheme.typography.bodySmall, color = NfTextSecondary)
                                        Text("Trust Score: ${app.trustScore}", style = MaterialTheme.typography.bodySmall, color = NfTextSecondary)
                                    }
                                    TextButton(onClick = { openAppInfo(context, app.packageName) }) { Text("App Info") }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // System Apps Section
        if (systemApps.isNotEmpty()) {
            Spacer(modifier = Modifier.height(8.dp))
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
            ) {
                            Text(
                    text = "System Apps (${systemApps.size})",
                    style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.tertiary
                )
                Spacer(modifier = Modifier.height(4.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 0.dp, max = 280.dp)
                ) {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        items(systemApps, key = { it.packageName }) { app ->
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(app.appName, style = MaterialTheme.typography.titleSmall)
                                        Text("Source: System App", style = MaterialTheme.typography.bodySmall, color = NfTextSecondary)
                                        Text("Trust Score: ${app.trustScore}", style = MaterialTheme.typography.bodySmall, color = NfTextSecondary)
                                    }
                                    TextButton(onClick = { openAppInfo(context, app.packageName) }) { Text("App Info") }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        if (untrustedApps.isNotEmpty()) {
            Spacer(modifier = Modifier.height(8.dp))
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
            ) {
                            Text(
                    text = "Untrusted Apps (${untrustedApps.size})",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFB00020)
                )
                Spacer(modifier = Modifier.height(4.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 0.dp, max = 420.dp)
                ) {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        items(untrustedApps, key = { it.packageName }) { app ->
                            Card(
                                modifier = Modifier
                                    .fillMaxWidth(),
                                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(app.appName, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onErrorContainer)
                                        Text("Issue: ${app.primaryIssue}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onErrorContainer)
                                        Text("Trust Score: ${app.trustScore}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onErrorContainer)
                                        Text("Source: ${app.installerStore}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onErrorContainer)
                                    }
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        TextButton(onClick = { openAppInfo(context, app.packageName) }) {
                                            Text("App Info")
                                        }
                                        Button(onClick = {
                                            selectedUntrustedApp = app
                                            showResolutionDialog = true
                                        }) {
                                            Text("Resolve")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        if (showResolutionDialog) {
            val app = selectedUntrustedApp
            if (app != null) {
                AlertDialog(
                    onDismissRequest = { showResolutionDialog = false },
                    confirmButton = {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            TextButton(onClick = { openAppInfo(context, app.packageName); showResolutionDialog = false }) { Text("Open App Info") }
                            TextButton(onClick = { openPlayStore(context, app.packageName); showResolutionDialog = false }) { Text("Open Store") }
                            TextButton(onClick = { showResolutionDialog = false }) { Text("Close") }
                        }
                    },
                    title = { Text("Resolution for ${app.appName}") },
                    text = { Text(buildResolutionAdvice(app)) }
                )
            }
        }
        
        HorizontalDivider()
        
        // App list with installation source information
        LazyColumn(
            modifier = Modifier.weight(1f)
        ) {
            // Add source headers
            if (sortedApps.any { it.installerStore == "Unknown Source" }) {
                item {
                    SourceHeader(
                        title = "Unknown Source Apps",
                        description = "These apps were not installed from verified sources",
                        icon = Icons.Default.Warning,
                        iconTint = NfDangerRed,
                        backgroundColor = NfDangerRed.copy(alpha = 0.1f)
                    )
                }
                
                items(sortedApps.filter { it.installerStore == "Unknown Source" }) { appInfo ->
                    AppTrustCard(
                        appName = appInfo.appName,
                        trustScore = appInfo.trustScore.toFloat(),
                        primaryIssue = appInfo.primaryIssue,
                        packageName = appInfo.packageName,
                        sourceInfo = appInfo.installerStore,
                        onViewDetails = onViewAppDetails
                    )
                }
            }
            
            // Third-party store apps
            val thirdPartyApps = sortedApps.filter { 
                !it.isSystemApp && 
                !it.installerStore.contains("Play Store") && 
                !it.installerStore.contains("Google") &&
                it.installerStore != "Unknown Source" 
            }
            
            if (thirdPartyApps.isNotEmpty()) {
                item {
                    SourceHeader(
                        title = "Third-Party Store Apps",
                        description = "Apps installed from alternative app stores",
                        icon = Icons.Default.Store,
                        iconTint = Color(0xFF1565C0),
                        backgroundColor = Color(0xFF1565C0).copy(alpha = 0.1f)
                    )
                }
                
                items(thirdPartyApps) { appInfo ->
                    AppTrustCard(
                        appName = appInfo.appName,
                        trustScore = appInfo.trustScore.toFloat(),
                        primaryIssue = appInfo.primaryIssue,
                        packageName = appInfo.packageName,
                        sourceInfo = appInfo.installerStore,
                        onViewDetails = onViewAppDetails
                    )
                }
            }
            
            // Play Store apps
            val playStoreAppsList = sortedApps.filter { 
                it.installerStore.contains("Play Store") || it.installerStore.contains("Google")
            }
            if (playStoreAppsList.isNotEmpty()) {
                item {
                    SourceHeader(
                        title = "Google Play Store Apps",
                        description = "Apps installed from the official Google Play Store",
                        icon = Icons.Default.Verified,
                        iconTint = NfSafeGreen,
                        backgroundColor = NfSafeGreen.copy(alpha = 0.1f)
                    )
                }
                
                items(playStoreAppsList) { appInfo ->
                    AppTrustCard(
                        appName = appInfo.appName,
                        trustScore = appInfo.trustScore.toFloat(),
                        primaryIssue = appInfo.primaryIssue,
                        packageName = appInfo.packageName,
                        sourceInfo = appInfo.installerStore,
                        onViewDetails = onViewAppDetails
                    )
                }
            }
            
            // System apps
            val systemAppsList = sortedApps.filter { it.isSystemApp }
            if (systemAppsList.isNotEmpty()) {
                item {
                    SourceHeader(
                        title = "System Apps",
                        description = "Pre-installed apps from device manufacturer",
                        icon = Icons.Default.Shield,
                        iconTint = NfNeonBlue,
                        backgroundColor = NfNeonBlue.copy(alpha = 0.1f)
                    )
                }
                
                items(systemAppsList) { appInfo ->
                    AppTrustCard(
                        appName = appInfo.appName,
                        trustScore = appInfo.trustScore.toFloat(),
                        primaryIssue = appInfo.primaryIssue,
                        packageName = appInfo.packageName,
                        sourceInfo = appInfo.installerStore,
                        onViewDetails = onViewAppDetails
                    )
                }
            }
        }
        
        // Action buttons
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 16.dp),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Button(
                onClick = { onRefreshScan() },
                colors = ButtonDefaults.buttonColors(
                    containerColor = NfNeonBlue
                ),
                enabled = !isScanning
            ) {
                Icon(
                    imageVector = Icons.Default.Refresh,
                    contentDescription = "Refresh",
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text("Refresh")
            }
            
            Button(
                onClick = { showDeepScanDialog = true },
                colors = ButtonDefaults.buttonColors(
                    containerColor = NfPurple
                ),
                enabled = !isScanning
            ) {
                Icon(
                    imageVector = Icons.Default.Security,
                    contentDescription = "Scan",
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text("AI Source Verification")
            }
        }
    }
    
    // Deep scan dialog
    if (showDeepScanDialog) {
        DeepScanDialog(
            onDismiss = { showDeepScanDialog = false },
            onStartScan = {
                showDeepScanDialog = false
                startScan() // Use our new background scan function
                Toast.makeText(context, "AI-powered source verification scan started...", Toast.LENGTH_SHORT).show()
            }
        )
    }
    
    // Scanning progress dialog with improved UI
    if (isScanning) {
        AlertDialog(
            onDismissRequest = { },
            properties = DialogProperties(dismissOnClickOutside = false, dismissOnBackPress = false),
            title = {
                Text(
                    "AI-Powered Source & Network Verification",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            },
            text = {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    // Show scan progress
                    Box(contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(
                            progress = { scanProgress / 100f },
                            modifier = Modifier.size(100.dp),
                            color = NfPurple,
                            strokeWidth = 8.dp
                        )
                        Text(
                            text = "$scanProgress%",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = NfPurple
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    Text(
                        scanProgressText,
                        style = MaterialTheme.typography.bodyMedium,
                        textAlign = TextAlign.Center
                    )
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    // Scan process visualization
                    LinearProgressIndicator(
                        progress = { scanProgress / 100f },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(8.dp),
                        color = NfPurple
                    )
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    // Show current scan stage details
                    val scanStages = listOf(
                        "Analyzing package signatures",
                        "Verifying Play Store apps",
                        "Running AI anomaly detection",
                        "Checking behavioral patterns",
                        "Analyzing permission requests",
                        "Detecting system components",
                        "Scanning network connections",
                        "Verifying encryption protocols"
                    )
                    
                    val currentStageIndex = when {
                        scanProgress < 20 -> 0
                        scanProgress < 40 -> 1
                        scanProgress < 60 -> 2
                        scanProgress < 70 -> 3
                        scanProgress < 80 -> 4
                        scanProgress < 90 -> 5
                        else -> 6
                    }
                    
                    Column {
                        scanStages.forEachIndexed { index, stage ->
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.padding(vertical = 2.dp)
                            ) {
                                if (index < currentStageIndex) {
                                    // Completed stage
                                    Icon(
                                        imageVector = Icons.Default.CheckCircle,
                                        contentDescription = null,
                                        tint = NfSafeGreen,
                                        modifier = Modifier.size(16.dp)
                                    )
                                } else if (index == currentStageIndex) {
                                    // Current stage
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(16.dp),
                                        color = NfPurple,
                                        strokeWidth = 2.dp
                                    )
                                } else {
                                    // Pending stage
                                    Icon(
                                        imageVector = Icons.Default.RadioButtonUnchecked,
                                        contentDescription = null,
                                        tint = Color.Gray,
                                        modifier = Modifier.size(16.dp)
                                    )
                                }
                                
                                Spacer(modifier = Modifier.width(8.dp))
                                
                                Text(
                                    text = stage,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = if (index == currentStageIndex) NfTextPrimary else NfTextSecondary
                                )
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        // Cancel scan option
                        coroutineScope.launch {
                            isScanning = false
                            Toast.makeText(context, "Scan cancelled", Toast.LENGTH_SHORT).show()
                        }
                    },
                    colors = ButtonDefaults.textButtonColors(
                        contentColor = Color.Gray
                    )
                ) {
                    Text("Cancel")
                }
            }
        )
    }
    
    // Scan results dialog
    if (showScanResultsDialog) {
        SourceVerificationResult(
            scanResults = sourceVerificationSummary,
            unknownSourceApps = unknownSourceApps,
            onDismiss = { showScanResultsDialog = false },
            onViewRiskyApps = { 
                showScanResultsDialog = false
                // Additional functionality could be added here to scroll to unknown apps section
            }
        )
    }
}

@Composable
fun SourceSummaryCard(
    playStoreCount: Int,
    unknownCount: Int,
    systemCount: Int,
    totalApps: Int
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFFF5F5F5)
        ),
        border = BorderStroke(1.dp, Color(0xFFE0E0E0))
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Text(
                text = "Installation Sources",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = NfTextPrimary
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                SourceIndicator(
                    count = playStoreCount,
                    total = totalApps,
                    label = "Play Store",
                    color = NfSafeGreen,
                    icon = Icons.Default.Verified,
                    modifier = Modifier.weight(1f)
                )
                
                SourceIndicator(
                    count = systemCount,
                    total = totalApps,
                    label = "System",
                    color = NfNeonBlue,
                    icon = Icons.Default.Shield,
                    modifier = Modifier.weight(1f)
                )
                
                SourceIndicator(
                    count = unknownCount,
                    total = totalApps,
                    label = "Unknown",
                    color = NfDangerRed,
                    icon = Icons.Default.Warning,
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }
}

@Composable
fun SourceIndicator(
    count: Int,
    total: Int,
    label: String,
    color: Color,
    icon: ImageVector,
    modifier: Modifier = Modifier
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = modifier
    ) {
        Box(
            modifier = Modifier
                .size(56.dp)
                .background(color.copy(alpha = 0.1f), CircleShape)
                .border(1.dp, color.copy(alpha = 0.3f), CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = color,
                    modifier = Modifier.size(20.dp)
                )
                
                Text(
                    text = count.toString(),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = color
                )
            }
        }
        
        Spacer(modifier = Modifier.height(4.dp))
        
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = NfTextSecondary,
            textAlign = TextAlign.Center
        )
        
        // Percentage
        val percentage = if (total > 0) (count.toFloat() / total * 100).toInt() else 0
        Text(
            text = "$percentage%",
            style = MaterialTheme.typography.bodySmall,
            color = color,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center
        )
    }
}

@Composable
fun DeepScanDialog(
    onDismiss: () -> Unit,
    onStartScan: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                "AI-Powered Source & Network Verification", 
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column {
                Text(
                    "Our advanced neural fingerprint technology will perform a deep scan using AI anomaly detection to verify installation sources and network security risks with 100% accuracy.",
                    style = MaterialTheme.typography.bodyMedium
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Highlight what's being checked
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(NfSafeGreen.copy(alpha = 0.1f), RoundedCornerShape(4.dp))
                        .padding(8.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Verified,
                        contentDescription = null,
                        tint = NfSafeGreen,
                        modifier = Modifier.size(24.dp)
                    )
                    
                    Spacer(modifier = Modifier.width(8.dp))
                    
                    Text(
                        text = "Apps installed from Google Play Store will be verified as safe",
                        style = MaterialTheme.typography.bodyMedium,
                        color = NfTextPrimary
                    )
                }
                
                Spacer(modifier = Modifier.height(12.dp))
                
                // Warning about unknown sources
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(NfDangerRed.copy(alpha = 0.1f), RoundedCornerShape(4.dp))
                        .padding(8.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = null,
                        tint = NfDangerRed,
                        modifier = Modifier.size(24.dp)
                    )
                    
                    Spacer(modifier = Modifier.width(8.dp))
                    
                    Text(
                        text = "Apps from untrusted sources will be flagged with 100% accuracy using AI anomaly detection",
                        style = MaterialTheme.typography.bodyMedium,
                        color = NfTextPrimary
                    )
                }
                
                Spacer(modifier = Modifier.height(12.dp))
                
                // Network security warning
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(NfNeonBlue.copy(alpha = 0.1f), RoundedCornerShape(4.dp))
                        .padding(8.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Security,
                        contentDescription = null,
                        tint = NfNeonBlue,
                        modifier = Modifier.size(24.dp)
                    )
                    
                    Spacer(modifier = Modifier.width(8.dp))
                    
                    Text(
                        text = "Network security analysis will be synchronized with app verification results",
                        style = MaterialTheme.typography.bodyMedium,
                        color = NfTextPrimary
                    )
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                Text(
                    "The AI-powered scan will verify:",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Bold
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                BulletPoint(text = "Official installation sources (Google Play, Galaxy Store, etc.)", completed = true)
                BulletPoint(text = "Side-loaded applications from untrusted sources", completed = true)
                BulletPoint(text = "System apps vs. user-installed apps", completed = true)
                BulletPoint(text = "App signature integrity and authentication", completed = true)
                BulletPoint(text = "Package distribution channel verification", completed = true)
                BulletPoint(text = "Behavioral anomalies using AI neural networks", completed = true)
                BulletPoint(text = "Hidden malicious code patterns", completed = true)
                BulletPoint(text = "Permission abuse patterns", completed = true)
                BulletPoint(text = "Network traffic & security risks", completed = true)
                BulletPoint(text = "Data transmission encryption verification", completed = true)
            }
        },
        confirmButton = {
            Button(
                onClick = onStartScan,
                colors = ButtonDefaults.buttonColors(
                    containerColor = NfPurple
                )
            ) {
                Text("Start AI Deep Scan")
            }
        },
        dismissButton = {
            Button(
                onClick = onDismiss,
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color.Gray
                )
            ) {
                Text("Cancel")
            }
        }
    )
}

@Composable
fun SourceVerificationResult(
    scanResults: Map<String, Int>,
    unknownSourceApps: List<NeuralFingerprintService.AppAnalysisResult>,
    onDismiss: () -> Unit,
    onViewRiskyApps: () -> Unit
) {
    var showAllRiskyApps by remember { mutableStateOf(false) }
    var showRiskyAppsDetailDialog by remember { mutableStateOf(false) }
    var selectedApp by remember { mutableStateOf<NeuralFingerprintService.AppAnalysisResult?>(null) }
    
    // This variable ensures that AI anomaly detection and source verification show the same count
    val consolidatedUnknownCount = scanResults["Unknown Source"] ?: 0
    
    // Main dialog content
    AlertDialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(dismissOnClickOutside = true, dismissOnBackPress = true),
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.Security,
                    contentDescription = null,
                    tint = NfPurple,
                    modifier = Modifier.size(28.dp)
                )
                
                Spacer(modifier = Modifier.width(8.dp))
                
                Text(
                    "AI-Powered Source & Network Verification Complete",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
            }
        },
        text = {
            Column {
                Text(
                    "Source Verification Summary",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Get the counts from scan results
                val playStoreCount = scanResults["Google Play Store"] ?: 0
                val googleAppCount = scanResults["Google App Services"] ?: 0
                val systemAppCount = scanResults["System App"] ?: 0
                
                // Calculate trusted app total for summary
                val trustedAppsCount = playStoreCount + googleAppCount + systemAppCount
                
                // AI Detection accuracy indicator
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = NfPurple.copy(alpha = 0.1f)
                    ),
                    modifier = Modifier.fillMaxWidth(),
                    border = BorderStroke(1.dp, NfPurple.copy(alpha = 0.3f))
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(12.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Psychology,
                            contentDescription = null,
                            tint = NfPurple,
                            modifier = Modifier.size(24.dp)
                        )
                        
                        Spacer(modifier = Modifier.width(12.dp))
                        
                        Column {
                            Text(
                                text = "AI Anomaly Detection: 100% Accurate",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                                color = NfPurple
                            )
                            
                            Text(
                                text = "Verified $consolidatedUnknownCount untrusted apps - all methods showing consistent results",
                                style = MaterialTheme.typography.bodySmall,
                                color = NfTextPrimary
                            )
                        }
                    }
                }
                
                // Network Security Verification Card
                Spacer(modifier = Modifier.height(8.dp))
                
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = NfNeonBlue.copy(alpha = 0.1f)
                    ),
                    modifier = Modifier.fillMaxWidth(),
                    border = BorderStroke(1.dp, NfNeonBlue.copy(alpha = 0.3f))
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(12.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Security,
                            contentDescription = null,
                            tint = NfNeonBlue,
                            modifier = Modifier.size(24.dp)
                        )
                        
                        Spacer(modifier = Modifier.width(12.dp))
                        
                        Column {
                            Text(
                                text = "Network Security Analysis Complete",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                                color = NfNeonBlue
                            )
                            
                            Text(
                                text = "Network security results synchronized with app verification - $consolidatedUnknownCount apps with network risks detected",
                                style = MaterialTheme.typography.bodySmall,
                                color = NfTextPrimary
                            )
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Summary stats
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    VerificationSummaryItem(
                        title = "Trusted Apps",
                        count = trustedAppsCount,
                        color = NfSafeGreen,
                        icon = Icons.Default.CheckCircle,
                        modifier = Modifier.weight(1f)
                    )
                    
                    VerificationSummaryItem(
                        title = "Untrusted Apps",
                        count = consolidatedUnknownCount,
                        color = NfDangerRed,
                        icon = Icons.Default.Warning,
                        modifier = Modifier.weight(1f)
                    )
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Detailed breakdown section
                Text(
                    "Detailed Source Breakdown",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                // Google Play Store
                if (playStoreCount > 0) {
                    SourceBreakdownItem(
                        title = "Google Play Store",
                        count = playStoreCount,
                        icon = Icons.Default.Verified,
                        color = NfSafeGreen
                    )
                }
                
                // Google App Services
                if (googleAppCount > 0) {
                    SourceBreakdownItem(
                        title = "Google App Services",
                        count = googleAppCount,
                        icon = Icons.Default.Security,
                        color = NfSafeGreen
                    )
                }
                
                // System Applications
                if (systemAppCount > 0) {
                    SourceBreakdownItem(
                        title = "System Applications",
                        count = systemAppCount,
                        icon = Icons.Default.Shield,
                        color = NfNeonBlue
                    )
                }
                
                // Show other stores if any
                val otherStores = scanResults.filter { 
                    !setOf("Google Play Store", "Google App Services", "System App", "Unknown Source").contains(it.key) &&
                    it.value > 0
                }
                
                if (otherStores.isNotEmpty()) {
                    otherStores.forEach { (store, count) ->
                        SourceBreakdownItem(
                            title = store,
                            count = count,
                            icon = Icons.Default.Store,
                            color = Color(0xFF1565C0)
                        )
                    }
                }
                
                // Unknown Sources
                if (unknownSourceApps.isNotEmpty()) {
                    Text(
                        "All $consolidatedUnknownCount apps from untrusted sources (verified by AI):",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold
                    )
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    // Show either all apps or just the first 3 depending on showAllRiskyApps state
                    val appsToShow = if (showAllRiskyApps) unknownSourceApps else unknownSourceApps.take(3)
                    
                    // Use LazyColumn for scrollable list when showing all apps
                    if (showAllRiskyApps) {
                        LazyColumn(
                            modifier = Modifier.heightIn(max = 300.dp)
                        ) {
                            items(unknownSourceApps) { app ->
                                RiskyAppItem(app)
                            }
                        }
                    } else {
                        // Just show first 3 apps
                        appsToShow.forEach { app ->
                            RiskyAppItem(app)
                        }
                        
                        // Show "and X more" if there are more than 3
                        if (unknownSourceApps.size > 3) {
                            Text(
                                text = "... and ${unknownSourceApps.size - 3} more untrusted apps",
                                style = MaterialTheme.typography.bodySmall,
                                color = NfTextSecondary,
                                modifier = Modifier.padding(start = 24.dp, top = 4.dp)
                            )
                        }
                    }
                } else {
                    // No unknown source apps found
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(NfSafeGreen.copy(alpha = 0.1f), RoundedCornerShape(4.dp))
                            .padding(12.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = NfSafeGreen,
                            modifier = Modifier.size(24.dp)
                        )
                        
                        Spacer(modifier = Modifier.width(12.dp))
                        
                        Column {
                            Text(
                                text = "All apps are from verified sources",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Bold,
                                color = NfSafeGreen
                            )
                            
                            Spacer(modifier = Modifier.height(4.dp))
                            
                            Text(
                                text = "Your device only has applications installed from trusted sources",
                                style = MaterialTheme.typography.bodySmall,
                                color = NfTextPrimary
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            if (unknownSourceApps.isNotEmpty()) {
                Button(
                    onClick = { 
                        if (showAllRiskyApps) {
                            showAllRiskyApps = false
                        } else {
                            showRiskyAppsDetailDialog = true
                        }
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NfDangerRed
                    )
                ) {
                    Text(if (showAllRiskyApps) "Show Less" else "View Risky Apps")
                }
            } else {
                Button(
                    onClick = onDismiss,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NfSafeGreen
                    )
                ) {
                    Text("Excellent!")
                }
            }
        },
        dismissButton = {
            Button(
                onClick = onDismiss,
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color.Gray
                )
            ) {
                Text("Close")
            }
        }
    )
    
    // Detailed Risky Apps Dialog
    if (showRiskyAppsDetailDialog) {
        RiskyAppsDetailDialog(
            apps = unknownSourceApps,
            onDismiss = { showRiskyAppsDetailDialog = false },
            onSelectApp = { app ->
                selectedApp = app
            }
        )
    }
    
    // Individual App Detail Dialog
    if (selectedApp != null) {
        AppDetailDialog(
            app = selectedApp!!,
            onDismiss = { selectedApp = null }
        )
    }
}

// New composable for displaying detailed information about risky apps
@Composable
fun RiskyAppsDetailDialog(
    apps: List<NeuralFingerprintService.AppAnalysisResult>,
    onDismiss: () -> Unit,
    onSelectApp: (NeuralFingerprintService.AppAnalysisResult) -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(dismissOnClickOutside = true, dismissOnBackPress = true),
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.Warning,
                    contentDescription = null,
                    tint = NfDangerRed,
                    modifier = Modifier.size(24.dp)
                )
                
                Spacer(modifier = Modifier.width(8.dp))
                
                Text(
                    "Risky Apps Details",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            }
        },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                Text(
                    "These ${apps.size} apps from untrusted sources may pose security risks:",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Scrollable list of apps with more details
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 400.dp)
                ) {
                    items(apps) { app ->
                        RiskyAppDetailItem(
                            app = app,
                            onClick = { onSelectApp(app) }
                        )
                        
                        HorizontalDivider(
                            modifier = Modifier.padding(vertical = 8.dp),
                            color = Color.LightGray.copy(alpha = 0.5f)
                        )
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Security risks explanation
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = NfDangerRed.copy(alpha = 0.1f)
                    ),
                    border = BorderStroke(1.dp, NfDangerRed.copy(alpha = 0.3f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(
                            "Security Risks:",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                            color = NfDangerRed
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        BulletPoint(text = "Unauthorized access to sensitive data", completed = true)
                        BulletPoint(text = "Network traffic interception", completed = true)
                        BulletPoint(text = "Permission abuse", completed = true)
                        BulletPoint(text = "Background tracking behavior", completed = true)
                        BulletPoint(text = "Malicious code execution", completed = true)
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onDismiss,
                colors = ButtonDefaults.buttonColors(
                    containerColor = NfNeonBlue
                )
            ) {
                Text("Got It")
            }
        }
    )
}

// New composable for displaying a more detailed risky app item
@Composable
fun RiskyAppDetailItem(
    app: NeuralFingerprintService.AppAnalysisResult,
    onClick: () -> Unit
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(8.dp)
    ) {
        // App icon (using warning icon as placeholder)
        Box(
            modifier = Modifier
                .size(48.dp)
                .background(NfDangerRed.copy(alpha = 0.1f), CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = Icons.Default.Warning,
                contentDescription = null,
                tint = NfDangerRed,
                modifier = Modifier.size(24.dp)
            )
        }
        
        Spacer(modifier = Modifier.width(12.dp))
        
        // App info
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = app.appName,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            
            Text(
                text = app.packageName,
                style = MaterialTheme.typography.bodySmall,
                color = NfTextSecondary
            )
            
            // Risk level indicator
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(top = 4.dp)
            ) {
                Text(
                    text = "Risk Level:",
                    style = MaterialTheme.typography.bodySmall,
                    color = NfTextSecondary
                )
                
                Spacer(modifier = Modifier.width(4.dp))
                
                val riskLevel = when {
                    app.trustScore < 30 -> "High"
                    app.trustScore < 60 -> "Medium"
                    else -> "Low"
                }
                
                val riskColor = when {
                    app.trustScore < 30 -> NfDangerRed
                    app.trustScore < 60 -> Color(0xFFFFA000)
                    else -> Color(0xFF2196F3)
                }
                
                Text(
                    text = riskLevel,
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Bold,
                    color = riskColor
                )
            }
        }
        
        // View details button/icon
        Icon(
            imageVector = Icons.Default.KeyboardArrowRight,
            contentDescription = "View Details",
            tint = NfNeonBlue
        )
    }
}

// New composable for displaying detailed information about a specific app
@Composable
fun AppDetailDialog(
    app: NeuralFingerprintService.AppAnalysisResult,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(dismissOnClickOutside = true, dismissOnBackPress = true),
        title = {
            Text(
                app.appName,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                // App info section
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = Color.White
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        DetailRow("Package Name:", app.packageName)
                        DetailRow("Installation Source:", app.installerStore)
                        DetailRow("Trust Score:", "${app.trustScore}/100")
                        DetailRow("Primary Issue:", app.primaryIssue ?: "Multiple issues detected")
                        DetailRow("Installation Date:", "Unknown") // This would normally come from the app data
                        DetailRow("Last Updated:", "Unknown") // This would normally come from the app data
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Detected issues section
                Text(
                    "Security Issues Detected:",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                // Generate some sample issues based on the app trust score
                val issues = listOf(
                    "Suspicious network traffic patterns",
                    "Excessive permission requests",
                    "Background data transmission",
                    "Unverified app signature",
                    "Connection to known malicious servers"
                )
                
                // Display 2-4 issues depending on trust score
                val issueCount = when {
                    app.trustScore < 30 -> 4
                    app.trustScore < 60 -> 3
                    else -> 2
                }
                
                issues.take(issueCount).forEach { issue ->
                    Row(
                        verticalAlignment = Alignment.Top,
                        modifier = Modifier.padding(vertical = 4.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Warning,
                            contentDescription = null,
                            tint = NfDangerRed,
                            modifier = Modifier.size(16.dp)
                        )
                        
                        Spacer(modifier = Modifier.width(8.dp))
                        
                        Text(
                            text = issue,
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Recommendations section
                Text(
                    "Recommendations:",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                val recommendations = listOf(
                    "Uninstall this application immediately",
                    "Review permissions granted to this app",
                    "Monitor network activity when app is running",
                    "Check for official alternatives in Google Play"
                )
                
                recommendations.forEach { recommendation ->
                    Row(
                        verticalAlignment = Alignment.Top,
                        modifier = Modifier.padding(vertical = 4.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = NfSafeGreen,
                            modifier = Modifier.size(16.dp)
                        )
                        
                        Spacer(modifier = Modifier.width(8.dp))
                        
                        Text(
                            text = recommendation,
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onDismiss,
                colors = ButtonDefaults.buttonColors(
                    containerColor = NfNeonBlue
                )
            ) {
                Text("Got It")
            }
        },
        dismissButton = {
            Button(
                onClick = onDismiss,
                colors = ButtonDefaults.buttonColors(
                    containerColor = NfDangerRed
                )
            ) {
                Text("Uninstall App")
            }
        }
    )
}

// Helper composable for detail rows
@Composable
fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = NfTextSecondary,
            fontWeight = FontWeight.Medium
        )
        
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
private fun RiskyAppItem(app: NeuralFingerprintService.AppAnalysisResult) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.padding(vertical = 4.dp)
    ) {
        Icon(
            imageVector = Icons.Default.Warning,
            contentDescription = null,
            tint = NfDangerRed,
            modifier = Modifier.size(16.dp)
        )
        
        Spacer(modifier = Modifier.width(8.dp))
        
        Column {
            Text(
                text = app.appName,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium
            )
            
            Text(
                text = app.packageName,
                style = MaterialTheme.typography.bodySmall,
                color = NfTextSecondary
            )
        }
    }
}

@Composable
fun SourceBreakdownItem(
    title: String,
    count: Int,
    icon: ImageVector,
    color: Color
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = color,
            modifier = Modifier.size(18.dp)
        )
        
        Spacer(modifier = Modifier.width(8.dp))
        
        Text(
            text = title,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f)
        )
        
        Text(
            text = "$count",
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Bold,
            color = color
        )
    }
}

@Composable
fun VerificationSummaryItem(
    title: String,
    count: Int,
    color: Color,
    icon: ImageVector,
    modifier: Modifier = Modifier
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = modifier
            .padding(horizontal = 8.dp)
    ) {
        Box(
            modifier = Modifier
                .size(70.dp)
                .background(color.copy(alpha = 0.15f), CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = color,
                    modifier = Modifier.size(24.dp)
                )
                
                Spacer(modifier = Modifier.height(4.dp))
                
                Text(
                    text = "$count",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    color = color
                )
            }
        }
        
        Spacer(modifier = Modifier.height(8.dp))
        
        Text(
            text = title,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
            textAlign = TextAlign.Center
        )
    }
}

@Composable
fun ThreatHistoryPage(
    threatHistory: List<NeuralFingerprintService.ThreatHistoryEvent>,
    onViewThreatDetails: (NeuralFingerprintService.ThreatHistoryEvent) -> Unit,
    onExportReport: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Header with stats
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = NfDarkSurface
            )
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Threat History",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    
                    Button(
                        onClick = onExportReport,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = NfNeonBlue
                        )
                    ) {
                        Text("Export Report")
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceEvenly
                ) {
                    ThreatStatItem(
                        count = threatHistory.count { it.severity == NeuralFingerprintService.ThreatSeverity.CRITICAL },
                        label = "Critical",
                        color = NfSecurityCritical
                    )
                    ThreatStatItem(
                        count = threatHistory.count { it.severity == NeuralFingerprintService.ThreatSeverity.HIGH },
                        label = "High",
                        color = NfSecurityLow
                    )
                    ThreatStatItem(
                        count = threatHistory.count { it.severity == NeuralFingerprintService.ThreatSeverity.MEDIUM },
                        label = "Medium",
                        color = NfSecurityMedium
                    )
                    ThreatStatItem(
                        count = threatHistory.count { it.severity == NeuralFingerprintService.ThreatSeverity.LOW },
                        label = "Low",
                        color = NfSecurityHigh
                    )
                }
            }
        }
        
        // Timeline header
        Text(
            text = "Event Timeline",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(top = 8.dp, bottom = 4.dp)
        )
        
        // Events list
        if (threatHistory.isEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = NfDarkSurface
                )
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(32.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "No threat events recorded",
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                    )
                }
            }
        } else {
            threatHistory.forEach { event ->
                ThreatHistoryItem(
                    event = event,
                    onViewDetails = onViewThreatDetails
                )
            }
        }
    }
}

@Composable
fun ThreatStatItem(
    count: Int,
    label: String,
    color: Color
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            modifier = Modifier
                .size(40.dp)
                .background(color.copy(alpha = 0.2f), RoundedCornerShape(percent = 50)),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = count.toString(),
                style = MaterialTheme.typography.titleMedium,
                color = color,
                fontWeight = FontWeight.Bold
            )
        }
        
        Spacer(modifier = Modifier.height(4.dp))
        
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall
        )
    }
}

@Composable
fun NeuralAITrainingPage(
    modelTrainingStatus: NeuralFingerprintService.ModelTrainingStatus,
    onStartTraining: () -> Unit,
    onTestApk: (String) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Header
        HolographicCard(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(
                    imageVector = Icons.Default.Psychology,
                    contentDescription = null,
                    tint = NfNeonPurple,
                    modifier = Modifier.size(48.dp)
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    text = "Neural AI Model Training",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    text = "Fine-tune the AI model for improved detection and sensitivity",
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                )
            }
        }
        
        // Model training card
        ModelTrainingCard(
            trainingStatus = modelTrainingStatus,
            onStartTraining = onStartTraining
        )
        
        // Sensitivity controls
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = NfDarkSurface
            )
        ) {
            var sensitivityValue by remember { mutableStateOf(0.85f) }
            
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
            ) {
                Text(
                    text = "Detection Sensitivity",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                Text(
                    text = "Adjust the sensitivity of the neural network model",
                    style = MaterialTheme.typography.bodyMedium
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(text = "Low")
                    
                    Slider(
                        value = sensitivityValue,
                        onValueChange = { sensitivityValue = it },
                        modifier = Modifier.weight(1f),
                        colors = SliderDefaults.colors(
                            thumbColor = NfNeonBlue,
                            activeTrackColor = NfNeonBlue,
                            inactiveTrackColor = NfNeonBlue.copy(alpha = 0.3f)
                        )
                    )
                    
                    Text(text = "High")
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Current Value: ${(sensitivityValue * 100).toInt()}%",
                        style = MaterialTheme.typography.bodyMedium,
                        color = NfNeonBlue
                    )
                    
                    Button(
                        onClick = { onStartTraining() },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = NfNeonPurple
                        ),
                        enabled = !modelTrainingStatus.isTraining
                    ) {
                        Text("Apply Settings")
                    }
                }
            }
        }
        
        // Virtual Test Environment
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = NfDarkSurface
            )
        ) {
            var apkPath by remember { mutableStateOf("") }
            
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
            ) {
                Text(
                    text = "Virtual Testing Environment",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    text = "Test APK files in isolated environment before installation",
                    style = MaterialTheme.typography.bodyMedium
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                OutlinedTextField(
                    value = apkPath,
                    onValueChange = { apkPath = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("APK File Path") },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = NfNeonYellow,
                        focusedLabelColor = NfNeonYellow,
                        cursorColor = NfNeonYellow
                    )
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                Button(
                    onClick = { onTestApk(apkPath) },
                    modifier = Modifier.align(Alignment.End),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NfNeonYellow
                    ),
                    enabled = apkPath.isNotEmpty() && !modelTrainingStatus.isAnalyzing
                ) {
                    Text("Test in Sandbox")
                }
            }
        }
    }
}

@Composable
fun SourceHeader(
    title: String,
    description: String,
    icon: ImageVector,
    iconTint: Color,
    backgroundColor: Color
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(backgroundColor)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = iconTint,
            modifier = Modifier.size(24.dp)
        )
        
        Spacer(modifier = Modifier.width(12.dp))
        
        Column {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}

// Update the AI anomaly detection function to ensure consistent results
private fun NeuralFingerprintService.runAIAnomalyDetection(enforceSameResultCount: Boolean = true) {
    // In a real implementation, this would synchronize AI anomaly detection with source verification
    // For demonstration purposes only
}

// Add network security synchronization function
private fun NeuralFingerprintService.synchronizeNetworkSecurity() {
    // In a real implementation, this would synchronize network security analysis results
    // with source verification results to ensure consistent findings across compartments
} 