package com.example.demo.student;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static  final List <Student> STUDENTS= Arrays.asList (
            new Student (1,"James, Bond"),
            new Student (2, "Maria, Jones"),
            new Student (3, "Anna, Smith")
    );

   @GetMapping
   public List<Student> getAllStudents(){
       return STUDENTS;
   }

   @PostMapping
   public void registerNewStudent(@RequestBody Student student){
       System.out.println (student);
   }

   @DeleteMapping("{studentId}")
   public  void deleteStudent(@PathVariable ("studentId" ) Integer studentId){
       System.out.println (studentId);
   }

   @PutMapping("{studentId}")
   public void updateStudent(@PathVariable ("studentId" )Integer studentId, @RequestBody Student student) {
       System.out.println (String.format ("%s %s",student, student));
   }
}