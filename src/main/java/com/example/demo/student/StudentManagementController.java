package com.example.demo.student;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/management/api/v1/students")
//@EnabledMethodSecurity()
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1,"Abdullah Turgut"),
            new Student(2,"Asya Turgut"),
            new Student(3,"Eray Turgut")
    );

    // hasRole('ROLE_') hasAnyRole('ROLE_') hasAuthority('permission') hasAnyAuthority('permission')
    @GetMapping
//    @PreAuthorize("hasAnyRole('ROLE_ADMIN, ROLE_ADMINTRAINEE')") // Bunlar AppSecurityConfig deki requestMatchers ile aynı işlevde
    public List<Student> getAllStudents() {
        System.out.println("getAllStudents");
        return STUDENTS;
    }
    @PostMapping
//    @PreAuthorize("hasAuthority('student:write')") // Bunlar AppSecurityConfig deki requestMatchers ile aynı işlevde
    public void registerNewStudent(@RequestBody Student student){
        System.out.println("registerNewStudent");
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
//    @PreAuthorize("hasAuthority('student:write')") // Bunlar AppSecurityConfig deki requestMatchers ile aynı işlevde
    public void deleteStudent(@PathVariable("studentId") Integer studentId){
        System.out.println("deleteStudent");
        System.out.println(studentId);
    }
    @PutMapping(path = "{studentId}")
//    @PreAuthorize("hasAuthority('student:write')") // Bunlar AppSecurityConfig deki requestMatchers ile aynı işlevde
    public void updateStudent(@PathVariable("studentId") Integer studentId,@RequestBody Student student){
        System.out.println("updateStudent");
        System.out.println(String.format("%s %s",studentId,student));
    }
}
