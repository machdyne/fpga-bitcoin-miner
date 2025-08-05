module pll(								
	input  clock_in,						
	output clock_out,						
	output locked // will go high when PLL is locked - has a stable voltage						
);								
									
    ECP5_PLL
    #( .IN_MHZ(48)
     , .OUT0_MHZ(64)
    // , .OUT0_MHZ(50)
     ) pll
     ( .clkin(clock_in)
     , .reset(1'b0)
     , .standby(1'b0)
     , .locked(locked)
     , .clkout0(clock_out)
     );

endmodule	
