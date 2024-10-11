package com.securenote.securenotes.Controllers;

import com.securenote.securenotes.Entities.AuditLog;
import com.securenote.securenotes.Services.AuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/audit")
public class AuditLogController {

    @Autowired
    AuditLogService auditLogService;

    @GetMapping
    public List<AuditLog> getAuditLogs() {
        return auditLogService.getAllAuditLogs();
    }

    @GetMapping("/note/{id}")
    public List<AuditLog> getAuditLogForNote(@PathVariable Long noteId) {
        return auditLogService.getAuditLogForNote(noteId);
    }
}
