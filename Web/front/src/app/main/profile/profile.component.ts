import { Component, OnInit } from '@angular/core'; 
import { Router } from '@angular/router'; 
import { AuthService } from 'src/app/services/auth.service'; 
import {ApiService} from '../../services/api.service' 
 
@Component({ 
  selector: 'app-profile', 
  templateUrl: './profile.component.html', 
  styleUrls: ['./profile.component.scss'] 
}) 
export class ProfileComponent implements OnInit { 
 
  constructor( 
    private _api : ApiService, 
    private _auth: AuthService, 
  ) { } 
 
  ngOnInit(): void { 
    this.test_jwt() 
  } 
 
  test_jwt(){ 
    this._api.getTypeRequest('test-jwt').subscribe((res: any) => { 
      console.log(res) 
 
    }, err => { 
      console.log(err) 
    }); 
  } 

  Archives(): void{
    console.log('hola');
    this._api.checkArchives().subscribe(resp => {
      console.log(resp)
    });
  }
  Users(): void{
    console.log('hola')
  }
  Sniffers(): void{
    console.log('hola')
  }
  Logs(): void{
    console.log('hola')
  }
  Mails(): void{
    console.log('hola')
  }
  Memory(): void{
    console.log('hola')
  }
  Temp(): void{
    console.log('hola')
  }
  DDOS(): void{
    console.log('hola')
  }
  CRON(): void{
    console.log('hola')
  }
  Invalid(): void{
    console.log('hola')
  }

}
