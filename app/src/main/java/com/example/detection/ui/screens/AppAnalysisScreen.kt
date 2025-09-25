package com.example.detection.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.detection.ui.components.*
import com.example.detection.ui.viewmodels.AppAnalysisInfo
import com.example.detection.ui.viewmodels.AppAnalysisState
import com.example.detection.ui.viewmodels.NeuralFingerprintViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppAnalysisScreen(
    onNavigateBack: () -> Unit,
    viewModel: NeuralFingerprintViewModel = viewModel()
) {
    val appAnalysisState by viewModel.appAnalysisState.collectAsStateWithLifecycle()
    var showDeepScanDialog by remember { mutableStateOf(false) }
    var selectedApp by remember { mutableStateOf<AppAnalysisInfo?>(null) }
    
    LaunchedEffect(Unit) {
        viewModel.refreshAppAnalysis()
    }
    
    if (showDeepScanDialog) {
        DeepScanDialog(
            onDismiss = { showDeepScanDialog = false },
            onConfirm = {
                // TODO: Implement deep scan functionality
                viewModel.runDeepScan()
            }
        )
    }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("App Analysis") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back"
                        )
                    }
                },
                actions = {
                    IconButton(onClick = { viewModel.refreshAppAnalysis() }) {
                        Icon(
                            imageVector = Icons.Default.Refresh,
                            contentDescription = "Refresh"
                        )
                    }
                }
            )
        }
    ) { padding ->
        when (appAnalysisState) {
            is AppAnalysisState.Loading -> {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator()
                }
            }
            
            is AppAnalysisState.Error -> {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "Error loading app data",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.error
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        Button(
                            onClick = { viewModel.refreshAppAnalysis() }
                        ) {
                            Text("Retry")
                        }
                    }
                }
            }
            
            is AppAnalysisState.Success -> {
                val data = (appAnalysisState as AppAnalysisState.Success).data
                val playStoreCount = data.count { it.installerStore.contains("Play Store") }
                val systemAppCount = data.count { it.isSystemApp }
                val unknownSourceCount = data.count { it.installerStore == "Unknown Source" }
                val otherStoreCount = data.count { 
                    !it.isSystemApp && 
                    !it.installerStore.contains("Play Store") && 
                    it.installerStore != "Unknown Source" 
                }
                
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding)
                        .padding(horizontal = 16.dp)
                ) {
                    item {
                        Spacer(modifier = Modifier.height(16.dp))
                        
                        SourceSummaryCard(
                            playStoreCount = playStoreCount,
                            systemAppCount = systemAppCount,
                            unknownSourceCount = unknownSourceCount,
                            otherStoreCount = otherStoreCount
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        WarningCard(
                            unknownSourceCount = unknownSourceCount,
                            onDeepScanClick = { showDeepScanDialog = true }
                        )
                        
                        Spacer(modifier = Modifier.height(16.dp))
                        
                        Text(
                            text = "Installed Applications",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                    }
                    
                    items(data.sortedBy { it.trustScore }.reversed()) { app ->
                        AppTrustCard(
                            app = app,
                            onClick = { selectedApp = app }
                        )
                    }
                    
                    item {
                        Spacer(modifier = Modifier.height(16.dp))
                    }
                }
                
                selectedApp?.let { app ->
                    AppDetailBottomSheet(
                        app = app,
                        onDismiss = { selectedApp = null },
                        onDeepScanClick = { showDeepScanDialog = true }
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppDetailBottomSheet(
    app: AppAnalysisInfo,
    onDismiss: () -> Unit,
    onDeepScanClick: () -> Unit
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Text(
                text = app.appName,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )
            
            Text(
                text = app.packageName,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            
            Spacer(modifier = Modifier.height(16.dp))
            
            DetailItem(
                title = "Installation Source",
                value = app.installerStore
            )
            
            DetailItem(
                title = "System App",
                value = if (app.isSystemApp) "Yes" else "No"
            )
            
            DetailItem(
                title = "Trust Score",
                value = "${app.trustScore}/100"
            )
            
            if (app.primaryIssue.isNotEmpty()) {
                DetailItem(
                    title = "Primary Issue",
                    value = app.primaryIssue
                )
            }
            
            if (app.dangerousPermissions.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    text = "Permissions Used",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                app.dangerousPermissions.forEach { permission ->
                    Text(
                        text = "• $permission",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(vertical = 2.dp)
                    )
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End
            ) {
                TextButton(
                    onClick = onDismiss
                ) {
                    Text("Close")
                }
                
                if (app.trustScore < 70) {
                    Spacer(modifier = Modifier.width(8.dp))
                    
                    Button(
                        onClick = onDeepScanClick
                    ) {
                        Text("Deep Scan")
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@Composable
fun DetailItem(
    title: String,
    value: String
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        
        Text(
            text = value,
            style = MaterialTheme.typography.bodyLarge
        )
        
        Spacer(modifier = Modifier.height(8.dp))
        
        HorizontalDivider()
    }
} 