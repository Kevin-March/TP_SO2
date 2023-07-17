import { BrowserModule } from '@angular/platform-browser'; 
import { NgModule } from '@angular/core'; 
import { AppRoutingModule } from './app-routing.module'; 
import { AppComponent } from './app.component'; 
import { LoginComponent } from './main/login/login.component'; 
import { ProfileComponent } from './main/profile/profile.component'; 
import { FormsModule, ReactiveFormsModule } from '@angular/forms'; 
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http'; 
import { InterceptorService } from './services/interceptor-service.service'; 
 
@NgModule({ 
  declarations: [ 
    AppComponent, 
    LoginComponent, 
    ProfileComponent, 
     
  ], 
  imports: [ 
    BrowserModule, 
    AppRoutingModule, 
    ReactiveFormsModule, 
    FormsModule, 
    HttpClientModule 
  ], 
  providers: [ 
    { 
      provide: HTTP_INTERCEPTORS, 
      useClass: InterceptorService, 
      multi: true 
    } 
  ], 
  bootstrap: [AppComponent] 
}) 


export class AppModule { }