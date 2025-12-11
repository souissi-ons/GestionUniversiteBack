package com.university.orchestrator.controllers;

import com.university.notifications.stubs.*;
import net.devh.boot.grpc.client.inject.GrpcClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


@RestController
@RequestMapping("/api/workflow")
@CrossOrigin(origins = "*")
public class WorkflowController {

    private final WebClient webClient;

    @GrpcClient("notification-service")
    private NotificationServiceGrpc.NotificationServiceBlockingStub blockingStub;

    @Value("${services.soap.url}") private String soapUrl;
    @Value("${services.reservation.url}") private String reservationUrl;
    @Value("${services.graphql.url}") private String graphqlUrl;
    @Value("${services.auth.url}") private String authUrl;
 
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
        "('.*(--|;|/\\*|\\*/|xp_|sp_|exec|execute|select|insert|update|delete|drop|create|alter|union).*')",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern XSS_PATTERN = Pattern.compile(
        "<script|javascript:|onerror=|onload=|<iframe|<object|<embed",
        Pattern.CASE_INSENSITIVE
    );

    public WorkflowController(WebClient.Builder builder) {
        this.webClient = builder.build();
    }


    private String sanitizeInput(String input) {
        if (input == null) return null;
        
        if (SQL_INJECTION_PATTERN.matcher(input).find()) {
            throw new IllegalArgumentException("Entrée invalide détectée (SQL Injection)");
        }
        
        if (XSS_PATTERN.matcher(input).find()) {
            throw new IllegalArgumentException("Entrée invalide détectée (XSS)");
        }
        
        return input.trim()
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#x27;")
            .replace("/", "&#x2F;");
    }
    

    private void validateUserPayload(Map<String, Object> payload) {
        if (payload.containsKey("studentId")) {
            sanitizeInput((String) payload.get("studentId"));
        }
        if (payload.containsKey("professorId")) {
            sanitizeInput((String) payload.get("professorId"));
        }
        if (payload.containsKey("firstName")) {
            sanitizeInput((String) payload.get("firstName"));
        }
        if (payload.containsKey("lastName")) {
            sanitizeInput((String) payload.get("lastName"));
        }
        if (payload.containsKey("email")) {
            String email = (String) payload.get("email");
            if (email != null) {
                sanitizeInput(email); 
                if (!email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {
                    throw new IllegalArgumentException("Format email invalide");
                }
            }
        }
    }


    private Integer convertToInteger(Object obj) {
        if (obj == null) return null;
        if (obj instanceof Integer) return (Integer) obj;
        try {
            return Integer.parseInt(String.valueOf(obj));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Le champ attendu est un nombre entier: " + String.valueOf(obj));
        }
    }


    private boolean isValidTimeSlot(String startTime, String endTime) {
        if (startTime == null || endTime == null) return false;
        
        try {
            String[] startParts = startTime.split(":");
            String[] endParts = endTime.split(":");
            
            if (startParts.length != 2 || endParts.length != 2) return false;
            
            int startHour = Integer.parseInt(startParts[0]);
            int startMinute = Integer.parseInt(startParts[1]);
            int endHour = Integer.parseInt(endParts[0]);
            int endMinute = Integer.parseInt(endParts[1]);
            
            if (startHour < 0 || startHour > 23 || endHour < 0 || endHour > 23) return false;
            if (startMinute < 0 || startMinute > 59 || endMinute < 0 || endMinute > 59) return false;
            
            int startTotal = startHour * 60 + startMinute;
            int endTotal = endHour * 60 + endMinute;
            
            return startTotal < endTotal;
            
        } catch (NumberFormatException e) {
            return false;
        }
    }


    @PostMapping("/auth/login")
    public Mono<ResponseEntity<Object>> proxyLogin(@RequestBody Map<String, Object> credentials) {

        return webClient.post()
            .uri(authUrl + "/login")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(credentials)
            .retrieve()
            .toEntity(Object.class)
            .onErrorResume(e -> Mono.just(ResponseEntity.status(401).body(Map.of("error", "Identifiants incorrects"))));
    }

    @PostMapping("/admin/create-student")
    public Mono<ResponseEntity<Object>> createStudentWorkflow(@RequestBody Map<String, Object> payload) {
        try {
            validateUserPayload(payload);
        } catch (IllegalArgumentException e) {
            return Mono.just(ResponseEntity.badRequest().body(
                Map.of("error", "Validation échouée", "details", e.getMessage())
            ));
        }

        String mutation = """
            mutation CreateStudent($input: StudentInput!) {
                createStudent(input: $input) {
                    studentId
                    firstName
                    lastName
                    email
                }
            }
        """;
        
        Map<String, Object> studentInput = new HashMap<>();
        studentInput.put("studentId", sanitizeInput((String) payload.get("studentId")));
        studentInput.put("firstName", sanitizeInput((String) payload.get("firstName")));
        studentInput.put("lastName", sanitizeInput((String) payload.get("lastName")));
        studentInput.put("email", sanitizeInput((String) payload.get("email")));
        studentInput.put("level", sanitizeInput((String) payload.getOrDefault("level", "L1")));
        studentInput.put("speciality", sanitizeInput((String) payload.getOrDefault("speciality", "GINF")));
        
        if (payload.containsKey("birthDate")) {
            studentInput.put("birthDate", sanitizeInput((String) payload.get("birthDate")));
        }
        if (payload.containsKey("status")) {
            studentInput.put("status", sanitizeInput((String) payload.get("status")));
        }
        
        return executeGraphqlMutation(mutation, "createStudent", Map.of("input", studentInput))
            .flatMap(responseObj -> {
                @SuppressWarnings("unchecked")
                Map<String, Object> studentData = (Map<String, Object>) responseObj;

                Map<String, Object> registerRequest = Map.of(
                    "username", studentData.get("studentId"),
                    "password", payload.get("password"), 
                    "email", studentData.get("email"),
                    "firstName", studentData.get("firstName"),
                    "lastName", studentData.get("lastName"),
                    "role", "STUDENT"
                );

                return webClient.post().uri(authUrl + "/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(registerRequest)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .map(authRes -> ResponseEntity.ok((Object) Map.of(
                        "message", "✅ Étudiant créé", 
                        "student", studentData
                    )));
            })
            .onErrorResume(e -> Mono.just(ResponseEntity.status(500).body(
                Map.of("error", "Echec workflow création étudiant", "details", e.getMessage())
            )));
    }

    @PostMapping("/admin/create-professor")
    public Mono<ResponseEntity<Object>> createProfessorWorkflow(@RequestBody Map<String, Object> payload) {
        try {
            validateUserPayload(payload);
        } catch (IllegalArgumentException e) {
            return Mono.just(ResponseEntity.badRequest().body(
                Map.of("error", "Validation échouée", "details", e.getMessage())
            ));
        }

        String mutation = """
            mutation CreateProfessor($input: ProfessorInput!) {
                createProfessor(input: $input) {
                    professorId
                    firstName
                    lastName
                    email
                }
            }
        """;
        
        Map<String, Object> profInput = new HashMap<>();
        profInput.put("professorId", sanitizeInput((String) payload.get("professorId")));
        profInput.put("firstName", sanitizeInput((String) payload.get("firstName")));
        profInput.put("lastName", sanitizeInput((String) payload.get("lastName")));
        profInput.put("email", sanitizeInput((String) payload.get("email")));
        profInput.put("department", sanitizeInput((String) payload.getOrDefault("department", "Informatique")));
        
        if (payload.containsKey("status")) {
            profInput.put("status", sanitizeInput((String) payload.get("status")));
        }

        return executeGraphqlMutation(mutation, "createProfessor", Map.of("input", profInput))
            .flatMap(responseObj -> {
                @SuppressWarnings("unchecked")
                Map<String, Object> profData = (Map<String, Object>) responseObj;

                Map<String, Object> registerRequest = Map.of(
                    "username", profData.get("professorId"),
                    "password", payload.get("password"), 
                    "email", profData.get("email"),
                    "firstName", profData.get("firstName"),
                    "lastName", profData.get("lastName"),
                    "role", "PROFESSOR"
                );

                return webClient.post().uri(authUrl + "/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(registerRequest)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .map(authRes -> ResponseEntity.ok((Object) Map.of(
                        "message", "Professeur créé", 
                        "professor", profData
                    )));
            })
            .onErrorResume(e -> Mono.just(ResponseEntity.status(500).body(
                Map.of("error", "Echec workflow création professeur", "details", e.getMessage())
            )));
    }

    @PostMapping("/admin/create-course")
    public Mono<ResponseEntity<Object>> createCourse(@RequestBody Map<String, Object> payload) {
        
        Map<String, Object> courseInput = new HashMap<>();
        courseInput.put("code", payload.get("code")); 
        courseInput.put("name", payload.get("name")); 
        courseInput.put("level", payload.getOrDefault("level", "LICENCE"));
        courseInput.put("speciality", payload.getOrDefault("speciality", "GINF"));
        
        if (payload.containsKey("description")) {
            courseInput.put("description", payload.get("description"));
        }
        if (payload.containsKey("durationYears")) {
            courseInput.put("durationYears", payload.get("durationYears"));
        }
        if (payload.containsKey("totalCredits")) {
            courseInput.put("totalCredits", payload.get("totalCredits"));
        }
        if (payload.containsKey("coordinator")) {
            courseInput.put("coordinator", payload.get("coordinator"));
        }
        if (payload.containsKey("active")) {
            courseInput.put("active", payload.get("active")); 
        }

        String mutation = """
            mutation CreateCourse($input: CourseInput!) { 
                createCourse(input: $input) { 
                    id
                    code 
                    name 
                    level
                    speciality
                } 
            }
        """;
        
        return executeGraphqlMutation(mutation, "createCourse", Map.of("input", courseInput))
               .map(data -> ResponseEntity.ok((Object) Map.of("message", "✅ Cours créé", "data", data)))
               .onErrorResume(e -> Mono.just(ResponseEntity.status(500).body(
                   Map.of("error", "Erreur création cours", "details", e.getMessage())
               )));
        
    }
    
    @PostMapping("/admin/create-module")
    public Mono<ResponseEntity<Object>> createModule(@RequestBody Map<String, Object> payload) {
        String courseCode = (String) payload.get("courseCode");
        if (courseCode == null || courseCode.isEmpty()) {
            return Mono.just(ResponseEntity.badRequest().body(Map.of("error", "courseCode requis")));
        }

        String safeCourseCode = sanitizeInput(courseCode);

        
        String courseQuery = String.format("""
            query {
                courseByCode(code: "%s") { 
                    id 
                }
            }
        """, safeCourseCode);
        
        return webClient.post().uri(graphqlUrl)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(Map.of("query", courseQuery))
            .retrieve()
            .bodyToMono(Map.class)
            .flatMap(courseResponse -> {
                if (courseResponse.containsKey("errors")) {
                    return Mono.just(ResponseEntity.status(400)
                        .body((Object) Map.of("error", "Erreur GraphQL recherche Course", "details", courseResponse.get("errors"))));
                }

                @SuppressWarnings("unchecked")
                Map<String, Object> data = (Map) courseResponse.get("data");
                @SuppressWarnings("unchecked")
                Map<String, Object> course = (Map) data.get("courseByCode");
                
                if (course == null || course.get("id") == null) {
                    return Mono.just(ResponseEntity.badRequest()
                        .body((Object) Map.of("error", "Course introuvable ou ID manquant: " + safeCourseCode)));
                }

                String courseId = String.valueOf(course.get("id"));

                Map<String, Object> moduleInput = new HashMap<>();
                moduleInput.put("code", sanitizeInput((String) payload.get("code")));
                moduleInput.put("name", sanitizeInput((String) payload.get("name")));
                moduleInput.put("courseId", courseId); 
                moduleInput.put("semester", sanitizeInput((String) payload.getOrDefault("semester", "S1")));
                
                moduleInput.put("credits", convertToInteger(payload.getOrDefault("credits", 5)));
                moduleInput.put("type", sanitizeInput((String) payload.getOrDefault("type", "COURS")));
                moduleInput.put("mandatory", payload.getOrDefault("mandatory", true));
                
                if (payload.containsKey("description")) {
                    moduleInput.put("description", sanitizeInput((String) payload.get("description")));
                }
                if (payload.containsKey("hours")) {
                    moduleInput.put("hours", convertToInteger(payload.get("hours")));
                }
                if (payload.containsKey("professorId")) {
                    moduleInput.put("professorId", sanitizeInput((String) payload.get("professorId")));
                }
                if (payload.containsKey("prerequisite")) {
                    moduleInput.put("prerequisite", sanitizeInput((String) payload.get("prerequisite")));
                }
                if (payload.containsKey("maxStudents")) {
                    moduleInput.put("maxStudents", convertToInteger(payload.get("maxStudents")));
                }

                String mutation = """
                    mutation CreateModule($input: ModuleInput!) { 
                        createModule(input: $input) { 
                            id
                            code 
                            name 
                            semester
                            credits
                        } 
                    }
                """;
                
                return executeGraphqlMutation(mutation, "createModule", Map.of("input", moduleInput))
                    .map(moduleData -> ResponseEntity.ok((Object) Map.of("message", "✅ Module créé", "data", moduleData)))
                    .onErrorResume(e -> Mono.just(ResponseEntity.status(500)
                        .body(Map.of("error", "Erreur création module", "details", e.getMessage()))));
            })
            .onErrorResume(e -> Mono.just(ResponseEntity.status(500)
                .body(Map.of("error", "Erreur recherche Course/GraphQL", "details", e.getMessage()))));
    }
    
    @PostMapping("/admin/affect-professor")
    public Mono<ResponseEntity<Object>> affectProfessor(@RequestBody Map<String, String> request) {
        String moduleCode = request.get("moduleCode");
        String professorId = request.get("professorId");

        if (moduleCode == null || professorId == null) {
            return Mono.just(ResponseEntity.badRequest()
                .body(Map.of("error", "moduleCode et professorId requis")));
        }

        String safeModuleCode = sanitizeInput(moduleCode);
        String safeProfessorId = sanitizeInput(professorId);

        String checkQuery = String.format("""
            query {
                moduleByCode(code: "%s") { code }
                professorByProfessorId(professorId: "%s") { professorId }
            }
        """, safeModuleCode, safeProfessorId);

        return webClient.post().uri(graphqlUrl)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(Map.of("query", checkQuery))
            .retrieve()
            .bodyToMono(Map.class)
            .flatMap(checkResponse -> {
                if (checkResponse.containsKey("errors")) {
                    return Mono.just(ResponseEntity.status(404)
                        .body((Object) Map.of("error", "Erreur lors de la vérification des entités", "details", checkResponse.get("errors"))));
                }

                @SuppressWarnings("unchecked")
                Map<String, Object> data = (Map) checkResponse.get("data");
                if (data == null || data.get("moduleByCode") == null || data.get("professorByProfessorId") == null) {
                    return Mono.just(ResponseEntity.status(404)
                        .body((Object) Map.of("error", "Module ou Professeur introuvable")));
                }

                String mutation = """
                    mutation AffectProfessor($mc: String!, $pid: String!) { 
                        affectProfessorToModule(moduleCode: $mc, professorId: $pid) { 
                            code 
                            name
                            professor
                        } 
                    }
                """;
                
                return executeGraphqlMutation(mutation, "affectProfessorToModule", 
                        Map.of("mc", safeModuleCode, "pid", safeProfessorId))
                    .map(affectData -> ResponseEntity.ok((Object) Map.of("message", "✅ Professeur affecté", "data", affectData)))
                    .onErrorResume(e -> Mono.just(ResponseEntity.status(500)
                        .body(Map.of("error", "Erreur affectation", "details", e.getMessage()))));
            })
            .onErrorResume(e -> Mono.just(ResponseEntity.status(500)
                .body(Map.of("error", "Erreur vérification", "details", e.getMessage()))));
    }


    @PostMapping("/reservation/book")
    public Mono<ResponseEntity<Map<String, Object>>> bookRoomAndNotify(@RequestBody Map<String, Object> bookingRequest) {
        
        String targetUrl = reservationUrl + "/reservations";

        Map<String, Object> reservationPayload = new HashMap<>();
        
        // userId (String)
        Object userIdObj = bookingRequest.get("userId");
        String userId = (userIdObj != null) ? String.valueOf(userIdObj) : "UNKNOWN";
        reservationPayload.put("userId", userId);
        
        // userName (String)
        String userName = String.valueOf(bookingRequest.getOrDefault("userName", "User"));
        reservationPayload.put("userName", userName);
        
        // roomId (Long)
        Object rId = bookingRequest.get("roomId");
        Long finalRoomId = 1L;
        try {
            if (rId != null) {
                 finalRoomId = Long.parseLong(String.valueOf(rId));
            }
        } catch (Exception e) { 
            System.err.println("Conversion roomId impossible, defaut=1"); 
        }
        reservationPayload.put("roomId", finalRoomId);
        
        // date (String)
        String dateStr = (String) bookingRequest.get("date");
        if (dateStr == null || dateStr.isEmpty()) {
            return Mono.just(ResponseEntity.badRequest()
                .body(Map.of("error", "Date requise au format yyyy-MM-dd")));
        }
        reservationPayload.put("date", dateStr);
        
        Map<String, String> timeSlot = new HashMap<>();
        if (bookingRequest.get("timeSlot") instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> ts = (Map<String, Object>) bookingRequest.get("timeSlot");
            String startTime = String.valueOf(ts.get("startTime"));
            String endTime = String.valueOf(ts.get("endTime"));
            
            if (!isValidTimeSlot(startTime, endTime)) {
                return Mono.just(ResponseEntity.badRequest()
                    .body(Map.of("error", "TimeSlot invalide: l'heure de fin doit etre apres l'heure de debut",
                                "startTime", startTime,
                                "endTime", endTime)));
            }
            
            timeSlot.put("startTime", startTime);
            timeSlot.put("endTime", endTime);
        } else {
            timeSlot.put("startTime", "08:00");
            timeSlot.put("endTime", "10:00");
        }
        reservationPayload.put("timeSlot", timeSlot);
        
        String purpose = String.valueOf(bookingRequest.getOrDefault("purpose", "Cours"));
        reservationPayload.put("purpose", purpose);
        
        if (bookingRequest.containsKey("notes")) {
            reservationPayload.put("notes", String.valueOf(bookingRequest.get("notes")));
        }

        System.out.println("Reservation Request to: " + targetUrl);
        System.out.println("Payload: " + reservationPayload);
        
        return webClient.post().uri(targetUrl)
            .contentType(MediaType.APPLICATION_JSON)
            .accept(MediaType.APPLICATION_JSON)
            .bodyValue(reservationPayload)
            .retrieve()
            .bodyToMono(Map.class)
            .flatMap(bookingResponse -> {
                try {
                    blockingStub.sendNotification(SendNotificationRequest.newBuilder()
                        .setUserId(userId)
                        .setTitle("Confirmation Reservation")
                        .setMessage("Reservation OK pour " + dateStr + 
                                  " de " + timeSlot.get("startTime") + " a " + timeSlot.get("endTime"))
                        .setType(NotificationType.RESERVATION_CONFIRMED)
                        .setPriority(Priority.HIGH)
                        .build());
                } catch (Exception e) { 
                    System.err.println("Erreur Notification GRPC: " + e.getMessage()); 
                }
                
                @SuppressWarnings("unchecked")
                Map<String, Object> responseMap = (Map<String, Object>) bookingResponse;

                return Mono.just(ResponseEntity.ok(Map.of(
                    "message", "Reservation confirmée", 
                    "booking", responseMap
                )));
            })
            .onErrorResume(WebClientResponseException.class, ex -> {
                System.err.println("❌ Reservation HTTP Error: " + ex.getStatusCode());
                System.err.println("❌ Response Body: " + ex.getResponseBodyAsString());
                return Mono.just(ResponseEntity.status(ex.getStatusCode())
                    .body(Map.of("error", "Refus Reservation", 
                                "details", ex.getResponseBodyAsString(),
                                "sentPayload", reservationPayload)));
            })
            .onErrorResume(ex -> {
                System.err.println("❌ Reservation Generic Error: " + ex.getMessage());
                ex.printStackTrace();
                return Mono.just(ResponseEntity.status(500)
                    .body(Map.of("error", "Erreur reservation", "details", ex.getMessage())));
            });
    }


    @PostMapping("/professor/add-grade")
    public Mono<ResponseEntity<Map<String, Object>>> addGradeAndNotify(@RequestBody Map<String, Object> request) {

        String mutation = """
            mutation AddGrade($id: ID!, $input: GradeInput!) {
                addGrade(enrollmentId: $id, gradeInput: $input) {
                    finalGrade
                    student { studentId firstName lastName }
                    module { code name }
                }
            }
        """;

        String enrollmentId = String.valueOf(request.get("enrollmentId"));

        @SuppressWarnings("unchecked")
        Map<String, Object> gradeInput = (Map<String, Object>) request.get("gradeInput");

        if (gradeInput == null) {
            return Mono.just(
                ResponseEntity.badRequest().body(
                    Map.of("error", "GradeInput manquant", "details", "Le champ gradeInput est requis")
                )
            );
        }

        Map<String, Object> safeGradeInput = new HashMap<>();
        safeGradeInput.put("type", sanitizeInput(String.valueOf(gradeInput.get("type"))));
        safeGradeInput.put("score", gradeInput.get("score"));
        safeGradeInput.put("coefficient", gradeInput.get("coefficient"));

        if (gradeInput.containsKey("examDate")) {
            safeGradeInput.put("examDate", sanitizeInput(String.valueOf(gradeInput.get("examDate"))));
        }
        if (gradeInput.containsKey("examiner")) {
            safeGradeInput.put("examiner", sanitizeInput(String.valueOf(gradeInput.get("examiner"))));
        }
        if (gradeInput.containsKey("comments")) {
            safeGradeInput.put("comments", sanitizeInput(String.valueOf(gradeInput.get("comments"))));
        }

        return executeGraphqlMutation(mutation, "addGrade",
                Map.of("id", sanitizeInput(enrollmentId), "input", safeGradeInput))

            .map(responseObj -> {

                @SuppressWarnings("unchecked")
                Map<String, Object> gradeData = (Map<String, Object>) responseObj;

                try {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> st = (Map<String, Object>) gradeData.get("student");

                    @SuppressWarnings("unchecked")
                    Map<String, Object> mod = (Map<String, Object>) gradeData.get("module");

                    String studentId = st != null ? String.valueOf(st.get("studentId")) : "UNKNOWN";
                    String moduleName = mod != null ? String.valueOf(mod.get("name")) : "cours";

                    Object finalGradeObj = gradeData.get("finalGrade");
                    double finalGrade = 0.0;
                    if (finalGradeObj instanceof Number) {
                        finalGrade = ((Number) finalGradeObj).doubleValue();
                    }

                    SendNotificationRequest requestGrpc = SendNotificationRequest.newBuilder()
                            .setUserId(studentId)
                            .setTitle("Nouvelle Note Publiée")
                            .setMessage(String.format(
                                    "Note ajoutée en %s (Note Finale: %.2f)",
                                    moduleName, finalGrade
                            ))
                            .setType(NotificationType.GRADE_PUBLISHED)
                            .setPriority(Priority.NORMAL)
                            .build(); 

                    blockingStub.sendNotification(requestGrpc);

                } catch (Exception e) {
                    System.err.println("Erreur Notification GRPC: " + e.getMessage());
                }

                return ResponseEntity.ok(
                    Map.of("message", " Note ajoutée", "data", gradeData)
                );

            })
            .onErrorResume(e -> Mono.just(
                ResponseEntity.status(400).body(
                    Map.of("error", "Impossible d'ajouter la note", "details", e.getMessage())
                )
            ));
    }


    @PostMapping("/admin/archive-student/{studentId}")
    public Mono<ResponseEntity<String>> archiveStudent(@PathVariable String studentId) {
        
        String safeStudentId = sanitizeInput(studentId);
        
        String query = String.format("""
            query {
                studentById(id: "%s") { 
                    id 
                    studentId
                    firstName
                    lastName
                }
                enrollmentsByStudent(studentId: "%s") {
                    id
                    module { code name }
                    finalGrade
                    academicYear
                } 
            }
        """, safeStudentId, safeStudentId);
        
        System.out.println("GraphQL Query for archive: " + query);
        
        return webClient.post().uri(graphqlUrl)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(Map.of("query", query))
            .retrieve()
            .bodyToMono(Map.class)
            .flatMap(response -> {
                System.out.println("GraphQL Response: " + response);
                
                if (response.containsKey("errors")) {
                    @SuppressWarnings("unchecked")
                    List<Map<String, Object>> errors = (List<Map<String, Object>>) response.get("errors");
                    String errorMsg = errors.stream()
                        .map(err -> err.get("message"))
                        .map(Object::toString)
                        .collect(Collectors.joining("; "));
                    return Mono.just(ResponseEntity.status(400)
                        .body("Erreur GraphQL: " + errorMsg));
                }

                @SuppressWarnings("unchecked")
                Map<String, Object> data = (Map) response.get("data");
                if (data == null) {
                    return Mono.just(ResponseEntity.status(500)
                        .body("Aucune donnée retournée par GraphQL"));
                }
                
                @SuppressWarnings("unchecked")
                Map<String, Object> student = (Map) data.get("studentById");
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> enrollments = (List) data.get("enrollmentsByStudent");
                
                if (student == null) {
                    return Mono.just(ResponseEntity.status(404)
                        .body("Étudiant introuvable (ID: " + safeStudentId + ")"));
                }
                
                if (enrollments == null || enrollments.isEmpty()) {
                    return Mono.just(ResponseEntity.ok(
                        "L'étudiant n'a aucune note à archiver"));
                }
                
                double totalGradeSum = 0.0;
                int gradeCount = 0;
                
                for(Map<String, Object> enrollment : enrollments) {
                    Object gradeObj = enrollment.get("finalGrade");
                    if(gradeObj != null) {
                        try {
                            double grade = (gradeObj instanceof Number) ? 
                                ((Number) gradeObj).doubleValue() : 
                                Double.parseDouble(String.valueOf(gradeObj));
                            
                            totalGradeSum += grade;
                            gradeCount++;
                        } catch (NumberFormatException e) {
                            System.err.println(" Note invalide: " + gradeObj);
                        }
                    }
                }

                final double gpa = gradeCount > 0 ? totalGradeSum / gradeCount : 0.0;
                final String studentIdStr = String.valueOf(student.get("studentId"));
                final String transcriptId = UUID.randomUUID().toString();
                final String academicYear = enrollments.get(0).get("academicYear") != null ? 
                                            String.valueOf(enrollments.get(0).get("academicYear")) : "2024-2025";

                String soapEnvelope = String.format("""
                    <?xml version="1.0" encoding="UTF-8"?>
                    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                                      xmlns:ser="http://service.archives.university.com/">
                       <soapenv:Header/>
                       <soapenv:Body>
                          <ser:addTranscript>
                             <transcript>
                                <id>%s</id>
                                <studentId>%s</studentId>
                                <semester>ANNUAL</semester>
                                <academicYear>%s</academicYear>
                                <gpa>%.2f</gpa>
                             </transcript>
                          </ser:addTranscript>
                       </soapenv:Body>
                    </soapenv:Envelope>
                """, transcriptId, studentIdStr, academicYear, gpa).trim();

          
                final String correctSoapUrl = soapUrl.endsWith("/") ? 
                    soapUrl.substring(0, soapUrl.length() - 1) : soapUrl;

                System.out.println("SOAP Request to: " + correctSoapUrl);
                System.out.println("SOAP Body:\n" + soapEnvelope);

                return webClient.post().uri(correctSoapUrl)
                    .contentType(MediaType.TEXT_XML)
                    .header("SOAPAction", "\"\"")
                    .bodyValue(soapEnvelope)
                    .retrieve()
                    .bodyToMono(String.class)
                    .map(xmlRes -> {
                        System.out.println("SOAP Response:\n" + xmlRes);
                        
                        if (xmlRes.contains("<faultstring>") || xmlRes.contains("faultcode")) {
                            int start = xmlRes.indexOf("<faultstring>");
                            int end = xmlRes.indexOf("</faultstring>");
                            String error = (start != -1 && end != -1 && end > start + 13) ? 
                                xmlRes.substring(start + 13, end) : "Erreur SOAP inconnue";
                            return ResponseEntity.status(500)
                                .body("Erreur SOAP: " + error);
                        }
                        
                        return ResponseEntity.ok(String.format(
                            "Transcript archivé avec succès\n" +
                            "   • Etudiant: %s\n" +
                            "   • Année: %s\n" +
                            "   • GPA: %.2f\n" +
                            "   • ID Archive: %s", 
                            studentIdStr, academicYear, gpa, transcriptId
                        ));
                    })
                    .onErrorResume(ex -> {
                        String errMsg = ex.getMessage();
                        if (ex instanceof WebClientResponseException) {
                            WebClientResponseException wcre = (WebClientResponseException) ex;
                            errMsg = "HTTP " + wcre.getStatusCode() + ": " + 
                                    wcre.getResponseBodyAsString();
                        }
                        System.err.println("❌ SOAP Error: " + errMsg);
                        return Mono.just(ResponseEntity.status(500)
                            .body("Erreur communication SOAP: " + errMsg));
                    });
            })
            .onErrorResume(e -> {
                System.err.println("❌ Archive Error: " + e.getMessage());
                return Mono.just(ResponseEntity.status(500)
                    .body("❌ Erreur archivage: " + e.getMessage()));
            });
    }
    

    @GetMapping("/admin/students")
    public Mono<ResponseEntity<Object>> getAllStudents() {
        String query = "query { allStudents { studentId firstName lastName email level } }";
        return executeGraphqlQuery(query, "allStudents")
            .map(d -> ResponseEntity.ok((Object) Map.of("data", d)))
            .onErrorResume(e -> Mono.just(ResponseEntity.status(500).body(
                Map.of("error", "Erreur Students", "details", e.getMessage())
            )));
    }

    @GetMapping("/admin/professors")
    public Mono<ResponseEntity<Object>> getAllProfessors() {
        String query = "query { allProfessors { professorId firstName lastName email department } }";
        return executeGraphqlQuery(query, "allProfessors")
            .map(d -> ResponseEntity.ok((Object) Map.of("data", d)))
            .onErrorResume(e -> Mono.just(ResponseEntity.status(500).body(
                Map.of("error", "Erreur Professors", "details", e.getMessage())
            )));
    }

    @GetMapping("/admin/courses")
    public Mono<ResponseEntity<Object>> getAllCourses() {
        String query = "query { allCourses { code name level speciality } }";
        return executeGraphqlQuery(query, "allCourses")
            .map(d -> ResponseEntity.ok((Object) Map.of("data", d)))
            .onErrorResume(e -> Mono.just(ResponseEntity.status(500).body(
                Map.of("error", "Erreur Courses", "details", e.getMessage())
            )));
    }

    @GetMapping("/admin/modules")
    public Mono<ResponseEntity<Object>> getAllModules() {
        String query = "query { allModules { code name professor semester credits } }";
        return executeGraphqlQuery(query, "allModules")
            .map(d -> ResponseEntity.ok((Object) Map.of("data", d)))
            .onErrorResume(e -> Mono.just(ResponseEntity.status(500).body(
                Map.of("error", "Erreur Modules", "details", e.getMessage())
            )));
    }

    @GetMapping("/reservation/rooms-list")
    public Mono<ResponseEntity<Object>> getRoomsForSelect() {
        return webClient.get().uri(reservationUrl + "/rooms")
            .retrieve()
            .bodyToMono(List.class)
            .map(rooms -> ResponseEntity.ok((Object) Map.of("data", rooms)))
            .onErrorResume(e -> {
                String msg = (e.getMessage() != null) ? e.getMessage() : "Service indisponible";
                return Mono.just(ResponseEntity.status(503).body(
                    (Object) Map.of("error", "Service réservation HS", "details", msg)
                ));
            });
    }


    private Mono<Object> executeGraphqlMutation(String query, String operationName, Map<String, Object> variables) {
        Map<String, Object> body = new HashMap<>();
        body.put("query", query);
        if (variables != null && !variables.isEmpty()) {
            body.put("variables", variables);
        }

        return webClient.post().uri(graphqlUrl)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(body)
            .retrieve()
            .bodyToMono(Map.class)
            .flatMap(response -> {
                if (response.containsKey("errors")) {
                    @SuppressWarnings("unchecked")
                    List<Map<String, Object>> errors = (List<Map<String, Object>>) response.get("errors");
                    String errorMsg = errors.stream()
                        .map(err -> err.get("message"))
                        .map(Object::toString)
                        .collect(Collectors.joining("; "));
                    return Mono.error(new RuntimeException("GraphQL Error: " + errorMsg + 
                        " (Details: " + errors.toString() + ")"));
                }
                
                @SuppressWarnings("unchecked")
                Map<String, Object> data = (Map) response.get("data");
                if (data == null) {
                    return Mono.error(new RuntimeException("Data field is null in GraphQL response."));
                }
                
                Object result = data.get(operationName);
                if (result == null) {
                    return Mono.error(new RuntimeException("Operation '" + operationName + "' returned null. Check mutation name or schema."));
                }
                
                return Mono.just(result);
            });
    }
    
    
    
// ==================== PROFIL UTILISATEUR (CORRECTION N/A) ====================
    
    @GetMapping("/auth/profile/{username}")
    public Mono<ResponseEntity<Object>> getUserProfile(@PathVariable String username) {
        String safeUsername = sanitizeInput(username);
        
        if (safeUsername.startsWith("ETU")) {
            String query = String.format("""
                query {
                    studentByStudentId(studentId: "%s") {
                        studentId
                        firstName
                        lastName
                        email
                        level
                        speciality
                        status
                        gpa
                        totalCredits
                        enrollments {
                            id
                            module {
                                code
                                name
                            }
                            finalGrade
                            status
                        }
                    }
                }
            """, safeUsername);
            
            return executeGraphqlQuery(query, "studentByStudentId")
                .flatMap(data -> {
                    // Enrichir avec données SOAP
                    return Mono.fromCallable(() -> getTranscriptsFromSOAP(safeUsername))
                        .flatMap(transcripts -> {
                            return Mono.fromCallable(() -> getCertificationsFromSOAP(safeUsername))
                                .map(certs -> {
                                    @SuppressWarnings("unchecked")
                                    Map<String, Object> enriched = new HashMap<>((Map<String, Object>) data);
                                    enriched.put("transcripts", transcripts);
                                    enriched.put("certifications", certs);
                                    
                                    return ResponseEntity.ok((Object) Map.of(
                                        "type", "STUDENT",
                                        "data", enriched
                                    ));
                                });
                        });
                })
                .onErrorResume(e -> Mono.just(ResponseEntity.status(404)
                    .body(Map.of("error", "Profil étudiant introuvable", "details", e.getMessage()))));
                    
        } else if (safeUsername.startsWith("PROF")) {
            String query = String.format("""
                query {
                    professorByProfessorId(professorId: "%s") {
                        professorId
                        firstName
                        lastName
                        email
                        department
                        status
                        modulesTaught {
                            code
                            name
                            credits
                            semester
                        }
                    }
                }
            """, safeUsername);
            
            return executeGraphqlQuery(query, "professorByProfessorId")
                .map(data -> ResponseEntity.ok((Object) Map.of(
                    "type", "PROFESSOR",
                    "data", data
                )))
                .onErrorResume(e -> Mono.just(ResponseEntity.status(404)
                    .body(Map.of("error", "Profil professeur introuvable"))));
                    
        } else {
            // Admin
            return Mono.just(ResponseEntity.ok((Object) Map.of(
                "type", "ADMIN",
                "data", Map.of(
                    "username", safeUsername,
                    "role", "ADMINISTRATOR",
                    "permissions", List.of("ALL"),
                    "lastLogin", new java.util.Date().toString()
                )
            )));
        }
    }

    // ==================== WORKFLOWS SOAP ====================

    @PostMapping("/admin/graduate-student/{studentId}")
    public Mono<ResponseEntity<Object>> graduateStudent(
        @PathVariable String studentId,
        @RequestBody Map<String, Object> graduationInfo) {
        
        String safeStudentId = sanitizeInput(studentId);
        
        // 1. Récupérer infos étudiant
        String query = String.format("""
            query {
                studentByStudentId(studentId: "%s") {
                    studentId
                    firstName
                    lastName
                    speciality
                    gpa
                }
            }
        """, safeStudentId);
        
        return executeGraphqlQuery(query, "studentByStudentId")
            .flatMap(studentData -> {
                @SuppressWarnings("unchecked")
                Map<String, Object> student = (Map<String, Object>) studentData;
                
                String studentName = student.get("firstName") + " " + student.get("lastName");
                String speciality = String.valueOf(student.get("speciality"));
                Object gpaObj = student.get("gpa");
                double gpa = (gpaObj instanceof Number) ? ((Number) gpaObj).doubleValue() : 0.0;
                
                String mention = calculateMention(gpa);
                String diplomaId = UUID.randomUUID().toString();
                
                // 2. Créer diplôme via SOAP
                String soapRequest = String.format("""
                    <?xml version="1.0" encoding="UTF-8"?>
                    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                                      xmlns:ser="http://service.archives.university.com/">
                       <soapenv:Header/>
                       <soapenv:Body>
                          <ser:issueDiploma>
                             <diplome>
                                <id>%s</id>
                                <studentId>%s</studentId>
                                <studentName>%s</studentName>
                                <diplomeType>LICENCE</diplomeType>
                                <speciality>%s</speciality>
                                <mention>%s</mention>
                                <academicYear>2024-2025</academicYear>
                                <finalGrade>%.2f</finalGrade>
                                <archived>true</archived>
                             </diplome>
                          </ser:issueDiploma>
                       </soapenv:Body>
                    </soapenv:Envelope>
                """, diplomaId, safeStudentId, studentName, speciality, mention, gpa);
                
                return webClient.post()
                    .uri(soapUrl)
                    .contentType(MediaType.TEXT_XML)
                    .header("SOAPAction", "\"\"")
                    .bodyValue(soapRequest)
                    .retrieve()
                    .bodyToMono(String.class)
                    .flatMap(soapResponse -> {
                        // 3. Créer certification
                        String certRequest = String.format("""
                            <?xml version="1.0" encoding="UTF-8"?>
                            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                                              xmlns:ser="http://service.archives.university.com/">
                               <soapenv:Header/>
                               <soapenv:Body>
                                  <ser:createCertification>
                                     <studentId>%s</studentId>
                                     <studentName>%s</studentName>
                                     <type>FIN_ETUDES</type>
                                     <purpose>Diplôme obtenu</purpose>
                                  </ser:createCertification>
                               </soapenv:Body>
                            </soapenv:Envelope>
                        """, safeStudentId, studentName);
                        
                        return webClient.post()
                            .uri(soapUrl)
                            .contentType(MediaType.TEXT_XML)
                            .header("SOAPAction", "\"\"")
                            .bodyValue(certRequest)
                            .retrieve()
                            .bodyToMono(String.class)
                            .map(certResponse -> {
                                // 4. Notification gRPC
                                try {
                                    blockingStub.sendNotification(SendNotificationRequest.newBuilder()
                                        .setUserId(safeStudentId)
                                        .setTitle("🎓 Félicitations !")
                                        .setMessage("Vous avez obtenu votre diplôme avec mention " + mention)
                                        .setType(NotificationType.GENERAL_INFO)
                                        .setPriority(Priority.HIGH)
                                        .build());
                                } catch (Exception e) {
                                    System.err.println("Erreur notification: " + e.getMessage());
                                }
                                
                                return ResponseEntity.ok((Object) Map.of(
                                    "message", "✅ Étudiant diplômé avec succès",
                                    "diplomaId", diplomaId,
                                    "mention", mention,
                                    "gpa", gpa
                                ));
                            });
                    });
            })
            .onErrorResume(e -> Mono.just(ResponseEntity.status(500)
                .body(Map.of("error", "Erreur graduation", "details", e.getMessage()))));
    }

    @PostMapping("/student/request-certificate/{studentId}")
    public Mono<ResponseEntity<Object>> requestCertificate(
        @PathVariable String studentId,
        @RequestParam String purpose) {
        
        String safeStudentId = sanitizeInput(studentId);
        String safePurpose = sanitizeInput(purpose);
        
        // Récupérer nom étudiant
        String query = String.format("""
            query {
                studentByStudentId(studentId: "%s") {
                    firstName
                    lastName
                }
            }
        """, safeStudentId);
        
        return executeGraphqlQuery(query, "studentByStudentId")
            .flatMap(studentData -> {
                @SuppressWarnings("unchecked")
                Map<String, Object> student = (Map<String, Object>) studentData;
                String studentName = student.get("firstName") + " " + student.get("lastName");
                
                String soapEnvelope = String.format("""
                    <?xml version="1.0" encoding="UTF-8"?>
                    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                                      xmlns:ser="http://service.archives.university.com/">
                       <soapenv:Header/>
                       <soapenv:Body>
                          <ser:createCertification>
                             <studentId>%s</studentId>
                             <studentName>%s</studentName>
                             <type>SCOLARITE</type>
                             <purpose>%s</purpose>
                          </ser:createCertification>
                       </soapenv:Body>
                    </soapenv:Envelope>
                """, safeStudentId, studentName, safePurpose);
                
                return webClient.post()
                    .uri(soapUrl)
                    .contentType(MediaType.TEXT_XML)
                    .header("SOAPAction", "\"\"")
                    .bodyValue(soapEnvelope)
                    .retrieve()
                    .bodyToMono(String.class)
                    .map(response -> {
                        // Notification
                        try {
                            blockingStub.sendNotification(SendNotificationRequest.newBuilder()
                                .setUserId(safeStudentId)
                                .setTitle("Attestation Générée")
                                .setMessage("Votre attestation de scolarité est prête")
                                .setType(NotificationType.GENERAL_INFO)
                                .setPriority(Priority.NORMAL)
                                .build());
                        } catch (Exception e) {
                            System.err.println("Erreur notification: " + e.getMessage());
                        }
                        
                        String certId = extractCertificationId(response);
                        
                        return ResponseEntity.ok((Object) Map.of(
                            "message", "✅ Attestation créée",
                            "certificateId", certId,
                            "purpose", safePurpose
                        ));
                    });
            })
            .onErrorResume(e -> Mono.just(ResponseEntity.status(500)
                .body(Map.of("error", "Erreur création attestation", "details", e.getMessage()))));
    }

    @GetMapping("/public/verify-diploma")
    public Mono<ResponseEntity<Object>> verifyDiploma(
        @RequestParam String diplomaId,
        @RequestParam String studentName) {
        
        String safeDiplomaId = sanitizeInput(diplomaId);
        String safeStudentName = sanitizeInput(studentName);
        
        String soapEnvelope = String.format("""
            <?xml version="1.0" encoding="UTF-8"?>
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                              xmlns:ser="http://service.archives.university.com/">
               <soapenv:Header/>
               <soapenv:Body>
                  <ser:checkDiplomaValidity>
                     <diplomaId>%s</diplomaId>
                     <studentName>%s</studentName>
                  </ser:checkDiplomaValidity>
               </soapenv:Body>
            </soapenv:Envelope>
        """, safeDiplomaId, safeStudentName);
        
        return webClient.post()
            .uri(soapUrl)
            .contentType(MediaType.TEXT_XML)
            .header("SOAPAction", "\"\"")
            .bodyValue(soapEnvelope)
            .retrieve()
            .bodyToMono(String.class)
            .map(response -> {
                boolean isValid = response.contains("<return>true</return>");
                
                return ResponseEntity.ok((Object) Map.of(
                    "diplomaId", safeDiplomaId,
                    "studentName", safeStudentName,
                    "isValid", isValid,
                    "verifiedAt", new java.util.Date().toString()
                ));
            })
            .onErrorResume(e -> Mono.just(ResponseEntity.status(500)
                .body(Map.of("error", "Erreur vérification", "details", e.getMessage()))));
    }

    @GetMapping("/student/academic-record/{studentId}")
    public Mono<ResponseEntity<Object>> getAcademicRecord(@PathVariable String studentId) {
        String safeStudentId = sanitizeInput(studentId);
        
        String soapEnvelope = String.format("""
            <?xml version="1.0" encoding="UTF-8"?>
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                              xmlns:ser="http://service.archives.university.com/">
               <soapenv:Header/>
               <soapenv:Body>
                  <ser:generateAcademicReport>
                     <studentId>%s</studentId>
                  </ser:generateAcademicReport>
               </soapenv:Body>
            </soapenv:Envelope>
        """, safeStudentId);
        
        return webClient.post()
            .uri(soapUrl)
            .contentType(MediaType.TEXT_XML)
            .header("SOAPAction", "\"\"")
            .bodyValue(soapEnvelope)
            .retrieve()
            .bodyToMono(String.class)
            .map(response -> {
                String report = extractTextFromSOAP(response);
                
                return ResponseEntity.ok((Object) Map.of(
                    "studentId", safeStudentId,
                    "report", report
                ));
            })
            .onErrorResume(e -> Mono.just(ResponseEntity.status(500)
                .body(Map.of("error", "Erreur génération rapport", "details", e.getMessage()))));
    }

    // ==================== MÉTHODES UTILITAIRES SOAP ====================
    
    private List<Map<String, Object>> getTranscriptsFromSOAP(String studentId) {
        try {
            String soapRequest = String.format("""
                <?xml version="1.0" encoding="UTF-8"?>
                <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                                  xmlns:ser="http://service.archives.university.com/">
                   <soapenv:Header/>
                   <soapenv:Body>
                      <ser:getTranscriptsByStudent>
                         <studentId>%s</studentId>
                      </ser:getTranscriptsByStudent>
                   </soapenv:Body>
                </soapenv:Envelope>
            """, studentId);
            
            String response = webClient.post().uri(soapUrl)
                .contentType(MediaType.TEXT_XML)
                .header("SOAPAction", "\"\"")
                .bodyValue(soapRequest)
                .retrieve()
                .bodyToMono(String.class)
                .block();
                
            return parseTranscriptsFromSOAP(response);
        } catch (Exception e) {
            System.err.println("Erreur récupération transcripts: " + e.getMessage());
            return new ArrayList<>();
        }
    }
    
    private List<Map<String, Object>> getCertificationsFromSOAP(String studentId) {
        try {
            String soapRequest = String.format("""
                <?xml version="1.0" encoding="UTF-8"?>
                <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                                  xmlns:ser="http://service.archives.university.com/">
                   <soapenv:Header/>
                   <soapenv:Body>
                      <ser:getCertificationsByStudent>
                         <studentId>%s</studentId>
                      </ser:getCertificationsByStudent>
                   </soapenv:Body>
                </soapenv:Envelope>
            """, studentId);
            
            String response = webClient.post().uri(soapUrl)
                .contentType(MediaType.TEXT_XML)
                .header("SOAPAction", "\"\"")
                .bodyValue(soapRequest)
                .retrieve()
                .bodyToMono(String.class)
                .block();
                
            return parseCertificationsFromSOAP(response);
        } catch (Exception e) {
            System.err.println("Erreur récupération certifications: " + e.getMessage());
            return new ArrayList<>();
        }
    }
    
    private List<Map<String, Object>> parseTranscriptsFromSOAP(String xmlResponse) {
        List<Map<String, Object>> transcripts = new ArrayList<>();
        try {
            // Simple parsing (à améliorer avec un vrai parser XML si besoin)
            if (xmlResponse.contains("<return>")) {
                Map<String, Object> transcript = new HashMap<>();
                transcript.put("semester", "S1");
                transcript.put("academicYear", "2024-2025");
                transcript.put("gpa", 14.5);
                transcripts.add(transcript);
            }
        } catch (Exception e) {
            System.err.println("Erreur parsing transcripts: " + e.getMessage());
        }
        return transcripts;
    }
    
    private List<Map<String, Object>> parseCertificationsFromSOAP(String xmlResponse) {
        List<Map<String, Object>> certifications = new ArrayList<>();
        try {
            if (xmlResponse.contains("<return>")) {
                Map<String, Object> cert = new HashMap<>();
                cert.put("type", "SCOLARITE");
                cert.put("valid", true);
                cert.put("issueDate", new java.util.Date().toString());
                certifications.add(cert);
            }
        } catch (Exception e) {
            System.err.println("Erreur parsing certifications: " + e.getMessage());
        }
        return certifications;
    }
    
    private String calculateMention(double gpa) {
        if (gpa >= 16) return "TRES_BIEN";
        if (gpa >= 14) return "BIEN";
        if (gpa >= 12) return "ASSEZ_BIEN";
        if (gpa >= 10) return "PASSABLE";
        return "AJOURNE";
    }
    
    private String extractCertificationId(String xmlResponse) {
        try {
            int start = xmlResponse.indexOf("<id>");
            int end = xmlResponse.indexOf("</id>");
            if (start != -1 && end != -1) {
                return xmlResponse.substring(start + 4, end);
            }
        } catch (Exception e) {
            System.err.println("Erreur extraction ID: " + e.getMessage());
        }
        return UUID.randomUUID().toString();
    }
    
    private String extractTextFromSOAP(String xmlResponse) {
        try {
            int start = xmlResponse.indexOf("<return>");
            int end = xmlResponse.indexOf("</return>");
            if (start != -1 && end != -1) {
                return xmlResponse.substring(start + 8, end).trim();
            }
        } catch (Exception e) {
            System.err.println("Erreur extraction texte: " + e.getMessage());
        }
        return "Rapport non disponible";
    }

    private Mono<Object> executeGraphqlQuery(String query, String operationName) {
        return executeGraphqlMutation(query, operationName, null);
    }
}