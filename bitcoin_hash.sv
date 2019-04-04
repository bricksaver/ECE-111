module bitcoin_hash(input logic clk, reset_n, start,
								input logic [15:0] message_addr, output_addr,
								output logic done, mem_clk, mem_we,
								output logic [15:0] mem_addr,
								output logic [31:0] mem_write_data,
								input logic [31:0] mem_read_data);
								
	// SHA256 K constants
	parameter int sha256_k[0:63] = '{
		32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
		32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
		32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
		32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
		32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
		32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
		32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
		32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
	};
	parameter NUM_NONCES = 8'd16;
	
	// hash op function - calculates values of Wt's once each time it is called
	function logic [255:0] sha256_op(input logic [31:0] a,b,c,d,e,f,g,sum);
		logic [31:0] s0,maj,t1,t2,s1,ch;
		//creating randomness
		s1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25);
		ch = (e & f) ^ ((~e) & g);
		t1 = ch + s1 + sum;
		s0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22);
		maj = (a & b) ^ (a & c) ^ (b & c);
		t2 = maj + s0;
		/*
		$display("Phase_#: a-h (sha_input): %h %h %h %h %h %h %h %h", a,b,c,d,e,f,g,h);
		//$display("t1: %h, t2: %h", t1,t2);
		$display("w: %h", w);
		$display("k: %h", k);
		//$display("ch: %h", ch);
		//$display("s1: %h", s1);
		//$display("h: %h", h);
		$display("Phase_#: a-h (sha_output): %h %h %h %h %h %h %h %h", t1 + t2, a, b, c, d + t1, e, f, g);
		//$display("s0: %h \n",s0);
		*/
		sha256_op = {t1+t2,a,b,c,d+t1,e,f,g};
	endfunction
	
	// right rotate function - right rotates values by amount specified
	
	function logic [31:0] rrot(input logic [31:0] word,
										input logic [7:0] rot_amount);
		rrot = (word>>rot_amount)|(word<<(32-rot_amount));
	endfunction
	
	logic [31:0] w[0:15]; //contains previous 16 w-values
	// calculates newest w-value
	function logic [31:0] wtnew(); // function with no inputs
	   logic [31:0] s0, s1;
		s0 = rrot(w[1],7)^rrot(w[1],18)^(w[1]>>3);
		s1 = rrot(w[14],17)^rrot(w[14],19)^(w[14]>>10);
		wtnew = w[0] + s0 + w[9] + s1;
	endfunction
	
	// initiate states
	enum logic [2:0] {IDLE,READ_1,READ_2,COMPUTE,WAIT,WRITE} state;
	
	// create registers to store variables
	logic [31:0] h0,h1,h2,h3,h4,h5,h6,h7;
	logic [31:0] h0_ph1,h1_ph1,h2_ph1,h3_ph1,h4_ph1,h5_ph1,h6_ph1,h7_ph1;
	logic [31:0] a,b,c,d,e,f,g,h;
	logic [31:0] sum;
	logic [15:0] temp_read_addr, temp_write_addr, temp_read_addr_sixteen;
	logic [7:0] t;
	logic [1:0] phase;
	logic [7:0] nonceCount;
	
	//Special Value
	logic [31:0] Nonce;
	
	// assignments
	assign mem_clk = clk;
	assign done = (state === IDLE);
	
	// always_ff
	always_ff @(posedge clk, negedge reset_n) begin
		if (!reset_n) begin
			state <= IDLE;
		end
		else begin
			case (state)
				IDLE: begin
					if (start) begin
						t <= 0;
						nonceCount <= 0;
						temp_read_addr <= message_addr;
						temp_read_addr_sixteen <= message_addr + 16'd16;
						temp_write_addr <= output_addr;
						Nonce <= 32'd0;
						phase <= 2'd1;
						state <= READ_1;
					end
				end
				READ_1: begin
					//state only called by phase 1 and 2
					if (phase === 1) begin
						// SHA256 Buffer Initiation - Initialize MD(Message Digest)
						h0_ph1 <= 32'h6a09e667;
						h1_ph1 <= 32'hbb67ae85;
						h2_ph1 <= 32'h3c6ef372;
						h3_ph1 <= 32'ha54ff53a;
						h4_ph1 <= 32'h510e527f;
						h5_ph1 <= 32'h9b05688c;
						h6_ph1 <= 32'h1f83d9ab;
						h7_ph1 <= 32'h5be0cd19;
						//read message word
						mem_addr <= temp_read_addr;
						mem_we <= 0;
						temp_read_addr <= temp_read_addr + 16'd1;
					end
					if (phase === 2) begin
						h0 <= h0_ph1;
						h1 <= h1_ph1;
						h2 <= h2_ph1;
						h3 <= h3_ph1;
						h4 <= h4_ph1;
						h5 <= h5_ph1;
						h6 <= h6_ph1;
						h7 <= h7_ph1;
						//read message word
						mem_addr <= temp_read_addr_sixteen;
						mem_we <= 0;
						temp_read_addr_sixteen <= temp_read_addr_sixteen + 16'd1;
					end
					state <= READ_2;
				end
				READ_2: begin
					if (phase === 1) begin
						// initialize a to h
						a <= h0_ph1;
						b <= h1_ph1;
						c <= h2_ph1;
						d <= h3_ph1;
						e <= h4_ph1;
						f <= h5_ph1;
						g <= h6_ph1;
						h <= h7_ph1;
						// read message word
						mem_addr <= temp_read_addr;
						mem_we <= 0;
						temp_read_addr <= temp_read_addr + 16'd1;
					end
					if (phase === 2) begin
						a <= h0;
						b <= h1;
						c <= h2;
						d <= h3;
						e <= h4;
						f <= h5;
						g <= h6;
						h <= h7;
						// read message word
						mem_addr <= temp_read_addr_sixteen;
						mem_we <= 0;
						temp_read_addr_sixteen <= temp_read_addr_sixteen + 16'd1;
					end
					state <= COMPUTE;
				end
				COMPUTE: begin
					case (phase)
						//phase1
						1: begin
							//compute block 1 from phase 1
							//t<=65
							if (t<66) begin
								//t<=63
								if (t<64) begin
									//t<=15 
									if (t<16) begin
										for (int n = 0; n < 15; n++) w[n] <= w[n+1];
											w[15] <= mem_read_data;
										/*
										$display("current 't' value: %d", t);
										$display("w for 0 to 15 calculated");
										*/
									end
									//16<=t<=63
									else begin
										for (int n = 0; n < 15; n++) w[n] <= w[n+1]; // just wires
											w[15] <= wtnew();
										/*
										$display("current 't' value: %d", t);
										$display("w for 16 to 63 is calculated");
										*/
									end
									//read another message word
									//t<=13
									if (t<14) begin
										mem_addr <= temp_read_addr;
										mem_we <= 0;
										temp_read_addr <= temp_read_addr + 16'd1;
									end
								end
							
								//***BEGIN PIPELINED CALCULATIONS***//
								//calculate hash_op - for t of previous cycle
								if (t >= 1 & t <= 64) begin
									$display("t: %d", t);
									//$display("k: %h", sha256_k[t-1]);
									//$display("W[15]: %h",w[15]);
									//$display("sum from %d: %h", t-1, sum);
									if (t == 1) begin
										sum <= h + sha256_k[t-1] + w[15];
									end
									//preuse g as h
									else begin
										sum <= g + sha256_k[t-1] + w[15];
									end
									//sum <= g + sha256_k[t-1] + w[15];
									//$display("h: %h", h);
									//$display("g: %h", g);
								end
								if (t >= 2 & t <= 65) begin
									//$display("t: %d", t-2);
									//$display("W[15]: %d",w[15]);
									{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, sum);
									//$display("SHA IS RUN");
								end
								//$display("Phase_1 Result - a-h: %h %h %h %h %h %h %h %h",a,b,c,d,e,f,g,h);
								//***END PIPELINED CALCULATIONS***//
								
								//prep for next cycle
								t <= t + 8'd1;
								state <= COMPUTE;
							end
							//finished current block
							else begin
								t <= 0;
								phase = 2'd2;
								//end of current block - update hash values
								h0_ph1 <= h0_ph1 + a;
								h1_ph1 <= h1_ph1 + b;
								h2_ph1 <= h2_ph1 + c;
								h3_ph1 <= h3_ph1 + d;
								h4_ph1 <= h4_ph1 + e;
								h5_ph1 <= h5_ph1 + f;
								h6_ph1 <= h6_ph1 + g;
								h7_ph1 <= h7_ph1 + h;
								//go to read_1 state
								state <= READ_1;
							end
						end
						//phase 2
						2: begin
							//compute block 2 from phase 2
							//$display("Phase_1 Result - h0-h7: %h %h %h %h %h %h %h %h", h0, h1, h2, h3, h4, h5, h6, h7);
							//$display("PHASE_2 - RUNNING");
							//t<=65
							if (t<66) begin
								//t<=63
								if (t<64) begin
									//t < num_words_last_block=3 (t<=2)
									if (t<3) begin
										for (int n = 0; n < 15; n++) w[n] <= w[n+1];
											w[15] <= mem_read_data;
									end
									//add 1 Nonce value (t=3)
									//num_words_last_block = 3;
									else if (t==3) begin
										for (int n = 0; n < 15; n++) w[n] <= w[n+1];
										w[15] <= Nonce;
										Nonce <= Nonce + 8'd1;
									end
									//pad with a 1 (t=4)
									//num_words_last_block = 3;
									else if (t==4) begin
										for (int n = 0; n < 15; n++) w[n] <= w[n+1];
										w[15] <= 32'h80000000;
									end
									//pad with 0's till 2nd last w[t] (5<=t<=14)
									//num_words_last_block = 3;
									else if (t>4 & t<=14) begin
										for (int n = 0; n < 15; n++) w[n] <= w[n+1];
										w[15] <= 32'h00000000;
									end
									//add 64-bit representation of message length to last w[t]
									else if (t>=15 & t<16) begin
										for (int n = 0; n < 15; n++) w[n] <= w[n+1];
										//final_block_ph2 = 32'd640
										w[15] <= 32'd640;
										/*
										$display("current 't' value: %d", t);
										$display("w for 0 to 15 calculated");
										*/
									end
									//16<=t<=63
									else begin
										for (int n = 0; n < 15; n++) w[n] <= w[n+1]; // just wires
											w[15] <= wtnew();
										/*
										$display("current 't' value: %d", t);
										$display("w for 16 to 63 is calculated");
										*/
									end
									//read another message word
									//note: will possibly read empty addresses, but necessary to account
									// for 1 word final blocks
									if (t<2) begin
										mem_addr <= temp_read_addr_sixteen;
										mem_we <= 0;
										temp_read_addr_sixteen <= temp_read_addr_sixteen + 16'd1;
									end
								end
								
								//***BEGIN PIPELINED CALCULATIONS***//
								//calculate hash_op - for t of previous cycle
								if (t >= 1 & t <= 64) begin
									// can do this because g preassigned to initial h value at start
									if (t == 1) begin
										sum <= h + sha256_k[t-1] + w[15];
									end
									//preuse g as h
									else begin
										sum <= g + sha256_k[t-1] + w[15];
									end
								end
								if (t >= 2 & t <= 65) begin	
									//$display("t: %d", t-1);
									{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, sum);
								end
								//***END PIPELINED CALCULATIONS***//
								
								//prep for next cycle
								t <= t + 8'd1;
								state <= COMPUTE;
							end
							//finished current block
							else begin
								t <= 0;
								phase = 2'd3;
								//end of current block - update hash values
								h0 <= h0 + a;
								h1 <= h1 + b;
								h2 <= h2 + c;
								h3 <= h3 + d;
								h4 <= h4 + e;
								h5 <= h5 + f;
								h6 <= h6 + g;
								h7 <= h7 + h;
								//done with second block - go to wait state then phase 3
								state <= WAIT;
							end
						end
						//phase3
						3: begin//$display("Phase_3 - NEW Constant h0-h7: %h %h %h %h %h %h %h %h", h0, h1, h2, h3, h4, h5, h6, h7);
							//$display("PHASE_3 - RUNNING");	
							if (t<66) begin
								//t<=63
								if (t<64) begin
									//t<=7
									if (t<8) begin
										case (t)
											0: begin
												for (int n = 0; n < 15; n++) w[n] <= w[n+1];
												w[15] <= h0;
											end
											1: begin
												for (int n = 0; n < 15; n++) w[n] <= w[n+1];
												w[15] <= h1;
											end
											2: begin
												for (int n = 0; n < 15; n++) w[n] <= w[n+1];
												w[15] <= h2;
											end
											3: begin
												for (int n = 0; n < 15; n++) w[n] <= w[n+1];
												w[15] <= h3;
											end
											4: begin
												for (int n = 0; n < 15; n++) w[n] <= w[n+1];
												w[15] <= h4;
											end
											5: begin
												for (int n = 0; n < 15; n++) w[n] <= w[n+1];
												w[15] <= h5;
											end
											6: begin
												for (int n = 0; n < 15; n++) w[n] <= w[n+1];
												w[15] <= h6;
											end
											7: begin
												for (int n = 0; n < 15; n++) w[n] <= w[n+1];
												w[15] <= h7;
											end
										endcase
									end
									//pad with a 1 (t=8)
									else if (t==8) begin
										// SHA256 Buffer Initiation - Initialize MD(Message Digest)
										h0 <= 32'h6a09e667;
										h1 <= 32'hbb67ae85;
										h2 <= 32'h3c6ef372;
										h3 <= 32'ha54ff53a;
										h4 <= 32'h510e527f;
										h5 <= 32'h9b05688c;
										h6 <= 32'h1f83d9ab;
										h7 <= 32'h5be0cd19;
										for (int n = 0; n < 15; n++) w[n] <= w[n+1];
										w[15] <= 32'h80000000;
									end
									//pad with 6 0's (9<=t<=14)
									else if (t>=9 & t<=14) begin
										for (int n = 0; n < 15; n++) w[n] <= w[n+1];
										w[15] <= 32'h00000000;
									end
									//add 64-bit representation of message length to last w[t]
									else if (t==15) begin
										for (int n = 0; n < 15; n++) w[n] <= w[n+1];
										//final_block_ph3 = 32'd256
										w[15] <= 32'd256;
										/*
										$display("current 't' value: %d", t);
										$display("w for 0 to 15 calculated");
										*/
									end
									//16<=t<=63
									else begin
										for (int n = 0; n < 15; n++) w[n] <= w[n+1]; // just wires
											w[15] <= wtnew();
										/*
										$display("current 't' value: %d", t);
										$display("w for 16 to 63 is calculated");
										*/
									end
								end
								
								//***BEGIN PIPELINED CALCULATIONS***//
								//calculate hash_op - for t of previous cycle
								if (t >= 1 & t <= 64) begin
									if (t == 1) begin
										sum <= h + sha256_k[t-1] + w[15];
									end
									//preuse g as h
									else begin
										sum <= g + sha256_k[t-1] + w[15];
									end
								end
								if (t >= 2 & t <= 65) begin	
									//$display("t: %d", t-1);
									{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, sum);
								end
								//***END PIPELINED CALCULATIONS***//
								
								//prep for next cycle
								t <= t + 8'd1;
								state <= COMPUTE;
							end
							//finished phase 3
							else begin
								t <= 0;
								phase = 2'd2;
								//end of phase 3 - update hash values
								h0 <= h0 + a;
								h1 <= h1 + b;
								h2 <= h2 + c;
								h3 <= h3 + d;
								h4 <= h4 + e;
								h5 <= h5 + f;
								h6 <= h6 + g;
								h7 <= h7 + h;
								//done with final block - prepare to write hash value (only h0)
								state <= WRITE;
							end
						end
					endcase
				end
				WAIT: begin
					//state called before state 3
					//update read_addr before phase 3 of every nonce iteration
					temp_read_addr <= message_addr;
					//assign a-h to constant h0-h7 values
					a <= 32'h6a09e667;
					b <= 32'hbb67ae85;
					c <= 32'h3c6ef372;
					d <= 32'ha54ff53a;
					e <= 32'h510e527f;
					f <= 32'h9b05688c;
					g <= 32'h1f83d9ab;
					h <= 32'h5be0cd19;
					state <= COMPUTE;
				end
				WRITE: begin
					/*
					$display("Write State - RUNNING");
					$display("nonceCount: %d", nonceCount);
					$display("Phase_3 Result - h0-h7: %h %h %h %h %h %h %h %h", h0, h1, h2, h3, h4, h5, h6, h7);
					*/
					mem_addr <= temp_write_addr + nonceCount;
					mem_write_data <= h0;
					mem_we <= 1;
					nonceCount <= nonceCount + 8'd1;
					if (nonceCount < 16) begin
						temp_read_addr <= message_addr;
						temp_read_addr_sixteen <= message_addr + 16'd16;
						state <= READ_1;
					end
					else begin
						temp_read_addr <= message_addr;
						temp_read_addr_sixteen <= message_addr + 16'd16;
						state <= IDLE;
					end
				end
			endcase
		end
	end
endmodule






